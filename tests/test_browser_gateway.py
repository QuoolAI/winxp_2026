"""Host-side bypass matrix for the XP25 browser egress gateway (vm/browser_gateway.py).

These exercise the *real* gateway process over its private UNIX socket and read its
own JSON decision log as independent, host-observed evidence. Each case asserts the
gateway's decision (allow/deny + reason) and the HTTP status it returns, so a policy
*denial* (403 + a logged `deny`) is always distinguished from an ordinary network
failure (a logged `error`, or a refused/aborted connection). No browser runs here.

Run as unittest for the pass/fail gates, or as a script with --evidence <dir> to
drive the whole matrix once against a fresh gateway and write a host-side evidence
bundle (decision log + per-case summary) under a private .work directory.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / 'vm/browser_gateway.py'
# AF_UNIX paths are capped near 108 bytes, so gateway sockets live in a short,
# private .work directory while logs and evidence keep their descriptive paths.
SOCKDIR = ROOT / '.work/gwsock'
_COUNTER = [0]


def _free_internet():
    """True when a direct TLS handshake to the documented example host succeeds,
    so the positive (allow) case is meaningful; skipped offline rather than failed."""
    try:
        with socket.create_connection(('example.com', 443), timeout=5) as raw:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname='example.com'):
                return True
    except OSError:
        return False


class Gateway:
    """A fresh gateway process on a private UNIX socket with a chosen allowlist."""

    def __init__(self, directory, allow, tag, tcp_clients=None):
        self.dir = Path(directory)
        SOCKDIR.mkdir(parents=True, exist_ok=True)
        _COUNTER[0] += 1
        self.sock = SOCKDIR / ('s%d.sock' % _COUNTER[0])
        self.log = self.dir / (tag + '.log')
        self.allow = list(allow) if allow != 'any' else 'any'
        # tcp_clients: listen on 127.0.0.1:<free port> and accept only these addresses.
        self.tcp_clients = tcp_clients
        self.port = None
        self.proc = None

    def __enter__(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        # A log left by an earlier run would satisfy the readiness wait below too early.
        for leftover in (self.sock, Path(str(self.sock) + '.policy.json'), self.log):
            if leftover.exists():
                leftover.unlink()
        if self.tcp_clients is None:
            cmd = [sys.executable, str(GATEWAY), '--socket', str(self.sock), '--log', str(self.log)]
        else:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                self.port = probe.getsockname()[1]
            cmd = [sys.executable, str(GATEWAY), '--listen', '127.0.0.1:%d' % self.port, '--log', str(self.log)]
            for client in self.tcp_clients:
                cmd += ['--client', client]
        if self.allow == 'any':
            cmd += ['--allow-any-public']
        for name in (self.allow if self.allow != 'any' else []):
            cmd += ['--allow', name]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(100):
            if self.port is None and self.sock.exists():
                break
            if self.port is not None and any(d.get('decision') == 'start' for d in self.decisions()):
                break
            if self.proc.poll() is not None:
                raise RuntimeError('gateway exited early: ' + self.proc.stdout.read().decode(errors='replace'))
            time.sleep(0.05)
        else:
            raise TimeoutError('gateway socket not created')
        return self

    def request(self, raw_request, do_tls_host=None, timeout=15):
        """Send one raw request head over the UNIX socket. Returns (status_line,
        tls_cert_or_None). When do_tls_host is set and the gateway answers 200, run a
        real TLS handshake through the tunnel and return the validated peer cert."""
        family = socket.AF_UNIX if self.port is None else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(self.sock) if self.port is None else ('127.0.0.1', self.port))
            client.sendall(raw_request)
            head = b''
            while b'\r\n\r\n' not in head and len(head) < 4096:
                chunk = client.recv(256)
                if not chunk:
                    break
                head += chunk
            status = head.split(b'\r\n', 1)[0].decode('latin-1') if head else ''
            cert = None
            if do_tls_host and status.endswith('200 Connection Established'):
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(client, server_hostname=do_tls_host) as tls:
                    cert = tls.getpeercert()
            return status, cert

    def decisions(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.proc and self.proc.stdout:
            self.proc.stdout.close()
        self.sock.unlink(missing_ok=True)
        Path(str(self.sock) + '.policy.json').unlink(missing_ok=True)


def connect(host):
    return ('CONNECT ' + host + ':443 HTTP/1.1\r\nHost: ' + host + ':443\r\n\r\n').encode('latin-1')


# (tag, allowlist, raw request, expected decision, expected reason-substring-or-None,
#  expects-403, description). reason is None when the decision is 'allow'.
CASES = [
    ('not_allowlisted_resolvable', ['example.com'], connect('example.org'),
     'deny', 'not_allowlisted', True,
     'A resolvable but non-allowlisted host is refused by policy (not by DNS failure)'),
    ('not_allowlisted_unresolvable', ['example.com'], connect('definitely-not-real.invalid'),
     'deny', 'not_allowlisted', True,
     'A non-allowlisted host is refused before any resolution is attempted'),
    ('direct_ip_public', ['example.com'], connect('93.184.216.34'),
     'deny', 'direct_ip_literal', True,
     'A literal public IP CONNECT cannot match a name allowlist (no direct-IP egress)'),
    ('direct_ip_metadata', ['example.com'], connect('169.254.169.254'),
     'deny', 'direct_ip_literal', True,
     'The cloud metadata IP is refused as a literal target'),
    ('direct_ip_loopback', ['example.com'], connect('127.0.0.1'),
     'deny', 'direct_ip_literal', True,
     'A loopback literal is refused as a literal target'),
    ('ipv6_literal', ['example.com'], connect('[2606:4700::1]'),
     'deny', 'malformed_or_wrong_method_or_port', True,
     'An IPv6 literal does not match a name:443 CONNECT and is refused'),
    ('wrong_port', ['example.com'], connect('example.com').replace(b':443', b':22'),
     'deny', 'malformed_or_wrong_method_or_port', True,
     'An allowlisted host on a non-443 port is refused (HTTPS-only egress)'),
    ('non_connect_verb', ['example.com'],
     b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
     'deny', 'malformed_or_wrong_method_or_port', True,
     'A non-CONNECT method is refused (no plaintext proxying)'),
    ('crlf_injection', ['example.com'],
     b'CONNECT example.com%0d%0aEvil:443 HTTP/1.1\r\n\r\n',
     'deny', 'malformed_or_wrong_method_or_port', True,
     'An encoded-CRLF host is refused by the strict request grammar'),
    ('non_global_allowlisted', ['localhost'], connect('localhost'),
     'deny', 'non_global_resolution', True,
     'Even an allowlisted name is refused when it resolves to a non-global address '
     '(DNS-rebind / internal-pivot defense)'),
]


def run_matrix(directory, include_positive):
    results = []
    for tag, allow, req, decision, reason, expect403, description in CASES:
        with Gateway(directory, allow, 'gw-' + tag) as gw:
            status, _ = gw.request(req)
            log = gw.decisions()
            last = log[-1] if log else {}
            ok = (last.get('decision') == decision
                  and (reason is None or reason in str(last.get('reason')))
                  and (('403' in status) == expect403))
            results.append({'case': tag, 'description': description, 'allowlist': allow,
                            'expected': {'decision': decision, 'reason': reason, 'http_403': expect403},
                            'observed': {'status': status, 'decision': last.get('decision'),
                                         'reason': last.get('reason')},
                            'pass': ok})
    if include_positive:
        with Gateway(directory, ['example.com'], 'gw-positive_allow') as gw:
            status, cert = gw.request(connect('example.com'), do_tls_host='example.com')
            log = gw.decisions()
            allow_rows = [d for d in log if d.get('decision') == 'allow' and d.get('host') == 'example.com']
            names = []
            if cert:
                names = [v for pair in cert.get('subjectAltName', ()) for v in pair[1:]]
            ok = bool(allow_rows) and '200 Connection Established' in status and 'example.com' in names
            results.append({'case': 'positive_allow', 'description':
                            'An allowlisted HTTPS host connects with end-to-end TLS preserved '
                            '(gateway never terminates TLS; real cert reaches the client)',
                            'allowlist': ['example.com'],
                            'expected': {'decision': 'allow', 'http_200': True, 'cert_for': 'example.com'},
                            'observed': {'status': status, 'allow_logged': bool(allow_rows),
                                         'resolved_ip': allow_rows[-1].get('ip') if allow_rows else None,
                                         'cert_subject_alt_names': names},
                            'pass': ok})
    return results


class GatewayBypassTests(unittest.TestCase):
    """Each negative class is a policy denial; the positive class preserves TLS."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(os.environ.get('XP25_GW_TEST_DIR', ROOT / '.work/gateway-unittests'))
        cls.dir.mkdir(parents=True, exist_ok=True)

    def _one(self, tag):
        case = next(c for c in CASES if c[0] == tag)
        tagn, allow, req, decision, reason, expect403, _ = case
        with Gateway(self.dir, allow, 'ut-' + tagn) as gw:
            status, _ = gw.request(req)
            last = (gw.decisions() or [{}])[-1]
        self.assertEqual(last.get('decision'), decision, (tag, status, last))
        if reason is not None:
            self.assertIn(reason, str(last.get('reason')), (tag, status, last))
        self.assertEqual('403' in status, expect403, (tag, status, last))

    def test_not_allowlisted_resolvable(self):
        self._one('not_allowlisted_resolvable')

    def test_not_allowlisted_unresolvable(self):
        self._one('not_allowlisted_unresolvable')

    def test_direct_ip_public(self):
        self._one('direct_ip_public')

    def test_direct_ip_metadata(self):
        self._one('direct_ip_metadata')

    def test_direct_ip_loopback(self):
        self._one('direct_ip_loopback')

    def test_ipv6_literal(self):
        self._one('ipv6_literal')

    def test_wrong_port(self):
        self._one('wrong_port')

    def test_non_connect_verb(self):
        self._one('non_connect_verb')

    def test_crlf_injection(self):
        self._one('crlf_injection')

    def test_non_global_allowlisted(self):
        self._one('non_global_allowlisted')

    def test_any_public_still_refuses_literal_ip(self):
        with Gateway(self.dir, 'any', 'ut-any-literal') as gw:
            status, _ = gw.request(connect('169.254.169.254'))
            last = (gw.decisions() or [{}])[-1]
        self.assertEqual((last.get('decision'), last.get('reason')), ('deny', 'direct_ip_literal'))
        self.assertIn('403', status)

    def test_any_public_still_refuses_non_global_name(self):
        with Gateway(self.dir, 'any', 'ut-any-local') as gw:
            status, _ = gw.request(connect('localhost'))
            last = (gw.decisions() or [{}])[-1]
        self.assertEqual((last.get('decision'), last.get('reason')), ('deny', 'non_global_resolution'))
        self.assertIn('403', status)

    def test_any_public_still_refuses_plain_http(self):
        with Gateway(self.dir, 'any', 'ut-any-http') as gw:
            status, _ = gw.request(b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n')
            last = (gw.decisions() or [{}])[-1]
        self.assertEqual(last.get('reason'), 'malformed_or_wrong_method_or_port')
        self.assertIn('403', status)

    def test_tcp_listener_refuses_other_clients(self):
        # The gateway serves only the named VM address; 127.0.0.1 is not it.
        with Gateway(self.dir, 'any', 'ut-tcp-other', tcp_clients=['127.0.0.2']) as gw:
            try:
                status, _ = gw.request(connect('example.com'), timeout=5)
            except OSError:
                status = ''
            rows = gw.decisions()
        self.assertEqual(status, '')
        self.assertTrue(any(r.get('reason') == 'client_not_allowed' and r.get('client') == '127.0.0.1' for r in rows), rows)

    def test_tcp_listener_serves_its_client(self):
        with Gateway(self.dir, 'any', 'ut-tcp-own', tcp_clients=['127.0.0.1']) as gw:
            status, _ = gw.request(connect('127.0.0.1'))
            last = (gw.decisions() or [{}])[-1]
        self.assertEqual(last.get('reason'), 'direct_ip_literal')
        self.assertIn('403', status)

    @unittest.skipUnless(_free_internet(), 'no direct Internet to the documented example host')
    def test_any_public_allows_an_unlisted_https_name(self):
        with Gateway(self.dir, 'any', 'ut-any-positive') as gw:
            status, cert = gw.request(connect('example.org'), do_tls_host='example.org')
        self.assertIn('200 Connection Established', status)
        names = [v for pair in (cert or {}).get('subjectAltName', ()) for v in pair[1:]]
        self.assertIn('example.org', names)

    @unittest.skipUnless(_free_internet(), 'no direct Internet to the documented example host')
    def test_positive_allow_preserves_tls(self):
        with Gateway(self.dir, ['example.com'], 'ut-positive') as gw:
            status, cert = gw.request(connect('example.com'), do_tls_host='example.com')
            allow_rows = [d for d in gw.decisions() if d.get('decision') == 'allow']
        self.assertTrue(allow_rows)
        self.assertIn('200 Connection Established', status)
        names = [v for pair in (cert or {}).get('subjectAltName', ()) for v in pair[1:]]
        self.assertIn('example.com', names)


def main():
    p = argparse.ArgumentParser(description='Drive the gateway bypass matrix and write host-side evidence.')
    p.add_argument('--evidence', type=Path, required=True)
    a = p.parse_args()
    out = a.evidence.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        p.error('private .work evidence directory required')
    out.mkdir(parents=True, exist_ok=True)
    results = run_matrix(out, include_positive=_free_internet())
    summary = {'gateway': str(GATEWAY), 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
               'internet_available': _free_internet(), 'cases': results,
               'passed': all(r['pass'] for r in results), 'case_count': len(results)}
    (out / 'gateway-bypass-matrix.json').write_text(json.dumps(summary, indent=2) + '\n')
    for r in results:
        print(('PASS' if r['pass'] else 'FAIL'), r['case'], '->', r['observed'].get('decision'),
              r['observed'].get('reason') or r['observed'].get('status'))
    print('TOTAL', sum(r['pass'] for r in results), '/', len(results),
          'internet=' + str(summary['internet_available']))
    return 0 if summary['passed'] else 2


if __name__ == '__main__':
    if '--evidence' in sys.argv:
        raise SystemExit(main())
    unittest.main()
