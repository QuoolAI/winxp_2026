"""Host checks for the XP25 AI components (ClippyAI, RoverAI, shared runtime).

They exercise the portable core, gateway authentication interop and the
cross-compiled PE contracts. They do not establish behavior on Windows XP;
that evidence comes from recorded guest runs.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
A = ROOT / 'components/xp25-agent'
R = ROOT / 'components/roverai'
CORE = [A / 'runtime/xp25_base.c', A / 'runtime/xp25_json.c', A / 'runtime/xp25_agent.c', A / 'llm/xp25_sha256.c',
        A / 'llm/xp25_llm.c', A / 'llm/xp25_offline.c', A / 'permissions/xp25_policy.c', R / 'indexer/rover_index.c',
        R / 'search/rover_query.c']
INCLUDES = ['-I', str(A / 'runtime'), '-I', str(A / 'llm'), '-I', str(A / 'permissions'), '-I', str(R / 'indexer'),
            '-I', str(R / 'search')]
STRICT = ['-std=c89', '-pedantic', '-Wall', '-Wextra', '-Werror', '-Wno-overlength-strings']
TOOLCHAIN = Path(os.environ.get('XP25_MINGW', ROOT / '.work/toolchains/mingw-binutils/usr/bin'))


def compiler(test):
    cc = shutil.which('cc')
    if not cc:
        test.skipTest('host C compiler unavailable')
    return cc


class PortableCoreTests(unittest.TestCase):
    def test_core_json_crypto_policy_agent_offline_and_rover(self):
        cc = compiler(self)
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            binary = Path(d) / 'ai_core'
            sanitize = ['-fsanitize=address,undefined'] if sys.platform.startswith('linux') else []
            subprocess.run([cc] + STRICT + sanitize + ['-g'] + INCLUDES + [str(ROOT / 'tests/ai_core.c')] +
                           [str(s) for s in CORE] + ['-o', str(binary)], check=True, capture_output=True)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('XP25_AI_CORE failures=0', run.stdout)

    def test_portable_core_has_no_windows_dependency(self):
        for source in CORE:
            text = source.read_text()
            self.assertNotIn('<windows.h>', text, source)


SIGNER = r'''
#include <stdio.h>
#include <string.h>
#include "xp25_llm.h"
#include "xp25_sha256.h"
int main(int argc, char **argv) {
    char sig[65], body[65];
    unsigned char secret[64];
    size_t n = xp25_hex_decode(argv[1], secret, sizeof(secret));
    (void)argc;
    xp25_gateway_sign(secret, n, "POST", argv[2], argv[3], argv[4], argv[5], strlen(argv[5]), sig, body);
    printf("%s %s\n", sig, body);
    return 0;
}
'''


class GatewayTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(A / 'gateway'))
        import xp25_gateway
        self.gw = xp25_gateway

    def test_c_signer_matches_gateway(self):
        cc = compiler(self)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            src = Path(d) / 'signer.c'
            src.write_text(SIGNER)
            binary = Path(d) / 'signer'
            subprocess.run([cc] + STRICT + INCLUDES + [str(src)] + [str(s) for s in CORE] + ['-o', str(binary)],
                           check=True, capture_output=True)
            secret = os.urandom(32)
            body = '{"model":"m","input":[{"role":"user","content":"hi \\u00e9"}]}'
            out = subprocess.check_output([str(binary), secret.hex(), '/xp25/v1/responses', 'ab' * 32, 'cd' * 16, body],
                                          text=True).split()
            self.assertEqual(out[0], self.gw.sign_request(secret, 'POST', '/xp25/v1/responses', 'ab' * 32, 'cd' * 16, body.encode()))
            self.assertEqual(out[1], hashlib.sha256(body.encode()).hexdigest())

    def free_port(self):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def wait_port(self, port):
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        self.fail('server did not start')

    def test_live_gateway_authenticates_and_forwards_with_store_false(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            d = Path(d)
            secret = os.urandom(32)
            (d / 'clients.json').write_text(json.dumps({'xp25': {'secret_hex': secret.hex()}}))
            mock_port, gw_port = self.free_port(), self.free_port()
            mock = subprocess.Popen([sys.executable, str(ROOT / 'vm/ai_mock_openai.py'), '--listen', '127.0.0.1:%d' % mock_port,
                                     '--key', 'sk-test', '--log', str(d / 'mock.jsonl')])
            gateway = subprocess.Popen([sys.executable, str(A / 'gateway/xp25_gateway.py'), '--listen', '127.0.0.1:%d' % gw_port,
                                        '--clients', str(d / 'clients.json'), '--upstream', 'http://127.0.0.1:%d' % mock_port,
                                        '--allow-insecure-loopback-upstream', '--log', str(d / 'gw.jsonl')],
                                       env=dict(os.environ, OPENAI_API_KEY='sk-test'), stdout=subprocess.DEVNULL)
            try:
                self.wait_port(mock_port)
                self.wait_port(gw_port)
                base = 'http://127.0.0.1:%d' % gw_port

                def call(body, sign_secret=secret, reuse=None):
                    challenge = reuse or json.load(urllib.request.urlopen(base + '/xp25/v1/challenge'))['challenge']
                    nonce = os.urandom(16).hex()
                    data = json.dumps(body).encode()
                    headers = {'X-XP25-Client': 'xp25', 'X-XP25-Challenge': challenge, 'X-XP25-Nonce': nonce,
                               'X-XP25-Content-SHA256': hashlib.sha256(data).hexdigest(), 'Content-Type': 'application/json',
                               'X-XP25-Signature': self.gw.sign_request(sign_secret, 'POST', '/xp25/v1/responses', challenge, nonce, data)}
                    req = urllib.request.Request(base + '/xp25/v1/responses', data=data, headers=headers, method='POST')
                    try:
                        reply = urllib.request.urlopen(req)
                        status, payload, sig = reply.status, reply.read(), reply.headers.get('X-XP25-Response-Signature')
                    except urllib.error.HTTPError as e:
                        status, payload, sig = e.code, e.read(), e.headers.get('X-XP25-Response-Signature')
                    return status, payload, sig, nonce, challenge

                body = {'model': 'm', 'store': True, 'input': [{'role': 'user', 'content': 'Show Event Viewer errors'}]}
                status, payload, sig, nonce, challenge = call(body)
                self.assertEqual(status, 200)
                self.assertEqual(sig, self.gw.sign_response(secret, nonce, 200, payload))
                self.assertEqual(json.loads(payload)['output'][0]['name'], 'eventlog_read')
                record = json.loads((d / 'mock.jsonl').read_text().splitlines()[-1])
                self.assertTrue(record['authorized'])
                self.assertIs(record['store'], False)          # gateway enforces store=false
                status, *_ = call(body, reuse=challenge)        # challenge is single use
                self.assertEqual(status, 401)
                status, *_ = call(body, sign_secret=os.urandom(32))
                self.assertEqual(status, 401)
                log = (d / 'gw.jsonl').read_text()
                self.assertNotIn('Show Event Viewer errors', log)  # bodies are never logged
            finally:
                for p in (gateway, mock):
                    p.terminate()
                    p.wait(timeout=10)

    def test_gateway_refuses_plain_http_to_non_loopback(self):
        with self.assertRaises(SystemExit):
            self.gw.Gateway({}, 'http://api.openai.com', 'k', True, 1, None, 1)

    def test_no_tls_validation_bypass_anywhere(self):
        for path in list(A.rglob('*.py')) + list(A.rglob('*.c')):
            text = path.read_text()
            for marker in ('CERT_NONE', 'check_hostname = False', '_create_unverified_context', 'SECURITY_FLAG_IGNORE'):
                self.assertNotIn(marker, text, path)


class CrossBuildTests(unittest.TestCase):
    def test_mingw_build_imports_resolve_against_guest_dlls(self):
        if not (TOOLCHAIN / 'i686-w64-mingw32-gcc-posix').is_file():
            self.skipTest('private MinGW toolchain unavailable')
        if not (ROOT / '.work/ai-20261025/guest-modules-01/WINDOWS/system32/kernel32.dll').is_file():
            self.skipTest('private guest module extraction unavailable')
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            out = Path(d) / 'build'
            run = subprocess.run([sys.executable, str(ROOT / 'build/ai_build.py'), '--toolchain', str(TOOLCHAIN),
                                  '--output', str(out), '--probe'], capture_output=True, text=True, timeout=900)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            result = json.loads((out / 'result.json').read_text())
            self.assertEqual(set(result['targets']), {'xp25agent.dll', 'ClippyAI.exe', 'RoverAI.exe', 'RoverAIBand.dll',
                                                      'XP25Broker.exe', 'ai_probe.exe'})
            for name, target in result['targets'].items():
                self.assertNotIn('libgcc_s_dw2-1.dll', target['imports'], name)
            self.assertIn('xp25agent.dll', result['targets']['ClippyAI.exe']['imports'])
            self.assertIn('xp25agent.dll', result['targets']['RoverAIBand.dll']['imports'])


if __name__ == '__main__':
    unittest.main()
