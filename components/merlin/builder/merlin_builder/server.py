"""MerlinAI Builder API: the control plane.

It authenticates installations (XP25-MERLIN1), validates and stores reports
and build requests, and lets an installation read and cancel only its own
jobs. It never investigates, builds or runs anything: the runner
(merlin_builder.runner) does that in a separate process, and the two share
only the job store. Deployment agents read job records and fetch update
content through their own credentials and only for the installations they
serve.

Every request body is untrusted. JSON is parsed with size limits and each
field is checked for type, length and character set before it is stored;
nothing from a request reaches a shell or a file name without validation."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import socket
import sys
from pathlib import Path

from . import protocol
from .store import ACTIVE, JOB, PROBLEM, Store, now

KINDS = {'crash', 'hang', 'service', 'kernel', 'shutdown', 'storage', 'driver', 'winlogon', 'security', 'event'}
SEVERITIES = {'critical', 'error', 'warning'}
TIME = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')


class Invalid(ValueError):
    pass


def text(value, limit, name, required=False):
    if value is None and not required:
        return ''
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise Invalid(name)
    if required and not value:
        raise Invalid(name)
    return value


def problem(p):
    """Validate one problem object (merlin_json_problem's shape)."""
    if not isinstance(p, dict):
        raise Invalid('problem')
    out = {'id': text(p.get('id'), 24, 'id', True)}
    if not PROBLEM.match(out['id']):
        raise Invalid('id')
    out['signature'] = text(p.get('signature'), 64, 'signature', True)
    if not HEX64.match(out['signature']):
        raise Invalid('signature')
    out['kind'] = text(p.get('kind'), 16, 'kind', True)
    out['severity'] = text(p.get('severity'), 12, 'severity', True)
    if out['kind'] not in KINDS or out['severity'] not in SEVERITIES:
        raise Invalid('kind/severity')
    for key, limit in (('component', 128), ('title', 256), ('impact', 256), ('app', 128), ('app_version', 64), ('module', 128),
                       ('module_version', 64), ('offset', 16), ('code', 16)):
        out[key] = text(p.get(key), limit, key)
    for key in ('first', 'last'):
        out[key] = text(p.get(key), 20, key)
        if out[key] and not TIME.match(out[key]):
            raise Invalid(key)
    count = p.get('count', 1)
    if not isinstance(count, int) or isinstance(count, bool) or not 0 < count <= 10 ** 7:
        raise Invalid('count')
    out['count'] = count
    for key in ('submitted', 'dump_consent'):
        if not isinstance(p.get(key, False), bool):
            raise Invalid(key)
        out[key] = p.get(key, False)
    evidence = p.get('evidence', [])
    if not isinstance(evidence, list) or len(evidence) > 24:
        raise Invalid('evidence')
    out['evidence'] = [text(e, 256, 'evidence') for e in evidence]
    occurrences = p.get('occurrences', [])
    if not isinstance(occurrences, list) or len(occurrences) > 32:
        raise Invalid('occurrences')
    out['occurrences'] = []
    for o in occurrences:
        if not isinstance(o, dict):
            raise Invalid('occurrence')
        t, ref = text(o.get('time'), 20, 'time'), text(o.get('ref'), 64, 'ref')
        if not TIME.match(t) or not ref or ' ' in ref:
            raise Invalid('occurrence')
        out['occurrences'].append({'time': t, 'ref': ref})
    return out


def manifest(m):
    if m is None:
        return {}
    if not isinstance(m, dict):
        raise Invalid('manifest')
    out = {'image_revision': text(m.get('image_revision'), 128, 'image_revision'), 'os': text(m.get('os'), 64, 'os'),
           'components': []}
    components = m.get('components', [])
    if not isinstance(components, list) or len(components) > 64:
        raise Invalid('components')
    for c in components:
        if not isinstance(c, dict):
            raise Invalid('component')
        entry = {'path': text(c.get('path'), 260, 'path', True)}
        if 'sha256' in c:
            entry['sha256'] = text(c.get('sha256'), 64, 'sha256')
            if not HEX64.match(entry['sha256']):
                raise Invalid('sha256')
        elif c.get('missing') is True:
            entry['missing'] = True
        else:
            raise Invalid('component state')
        out['components'].append(entry)
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = 'MerlinAI-Builder/1'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    # ---- plumbing ----
    def log_message(self, fmt, *args):
        self.server.log({'event': 'http', 'client': self.client_address[0], 'line': fmt % args})

    def reply(self, status, data, key=None, nonce=None, label=protocol.LABEL_BUILDER, raw=None, content_type='application/json'):
        body = raw if raw is not None else json.dumps(data, sort_keys=True).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        if key is not None:
            self.send_header('X-Merlin-Signature', protocol.sign_response(label, key, nonce, status, body))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def read_body(self, limit):
        length = self.headers.get('Content-Length')
        if length is None or not length.isdigit() or int(length) > limit:
            raise OverflowError('body too large or without length')
        body = self.rfile.read(int(length))
        if len(body) != int(length):
            raise OverflowError('short body')
        return body

    def do_GET(self):
        self.dispatch('GET')

    def do_POST(self):
        self.dispatch('POST')

    def dispatch(self, method):
        path = self.path
        limits = self.server.limits
        if path == '/merlin/v1/challenge' and method == 'GET':
            try:
                return self.reply(200, {'challenge': self.server.challenges.issue()})
            except OverflowError:
                return self.reply(503, {'error': 'busy'})
        try:
            body = self.read_body(limits['max_dump_bytes'] if path.endswith('/dump') else limits['max_request_bytes']) \
                if method == 'POST' else b''
        except OverflowError as e:
            self.server.log({'event': 'rejected', 'client': self.client_address[0], 'path': path[:80], 'reason': str(e)})
            return self.reply(413, {'error': 'request_too_large'})
        agent = path.startswith('/merlin/v1/agent/')
        try:
            if agent:
                principal, nonce, key = protocol.check_request(protocol.LABEL_BUILDER, self.server.store.agent_key,
                                                               self.server.challenges, method, path, self.headers, body)
            else:
                principal, nonce, key = protocol.check_request(protocol.LABEL_BUILDER, self.server.store.key,
                                                               self.server.challenges, method, path, self.headers, body)
        except PermissionError as e:
            self.server.log({'event': 'unauthenticated', 'client': self.client_address[0], 'path': path[:80], 'reason': str(e)})
            return self.reply(401, {'error': str(e)})
        self.server.log({'event': 'request', 'principal': principal, 'method': method, 'path': path[:120], 'bytes': len(body)})
        try:
            status, data, raw, ctype = (self.agent_route if agent else self.route)(principal, method, path, body)
        except Invalid as e:
            status, data, raw, ctype = 400, {'error': 'invalid_request', 'field': str(e)}, None, 'application/json'
        except OverflowError as e:
            status, data, raw, ctype = 429, {'error': 'quota', 'detail': str(e)}, None, 'application/json'
        except (ValueError, KeyError) as e:
            status, data, raw, ctype = 400, {'error': 'invalid_request', 'detail': type(e).__name__}, None, 'application/json'
        return self.reply(status, data, key, nonce, raw=raw, content_type=ctype)

    # ---- installations ----
    def route(self, inst, method, path, body):
        store = self.server.store
        parts = path.split('/')[3:]                 # after /merlin/v1
        if method == 'POST' and parts == ['reports']:
            data = json.loads(body)
            if not isinstance(data, dict) or data.get('schema') != 'xp25-merlin-report/1':
                raise Invalid('schema')
            items = data.get('problems')
            if not isinstance(items, list) or not 0 < len(items) <= 64:
                raise Invalid('problems')
            problems = [problem(p) for p in items]
            accepted = store.save_reports(inst, problems)
            self.server.log({'event': 'reports', 'installation': inst, 'accepted': len(accepted)})
            return 200, {'accepted': accepted, 'build_started': False}, None, 'application/json'
        if method == 'POST' and len(parts) == 3 and parts[0] == 'reports' and parts[2] == 'dump':
            store.save_dump(inst, parts[1], body)
            return 200, {'stored': len(body)}, None, 'application/json'
        if method == 'POST' and parts == ['jobs']:
            data = json.loads(body)
            if not isinstance(data, dict) or data.get('schema') != 'xp25-merlin-build/1':
                raise Invalid('schema')
            items = data.get('problems')
            if not isinstance(items, list) or not 0 < len(items) <= 32:
                raise Invalid('problems')
            problems = [problem(p) for p in items]
            request = data.get('request') or {}
            if not isinstance(request, dict):
                raise Invalid('request')
            req = {'explanation': text(request.get('explanation'), 2048, 'explanation'),
                   'requested_by': text(request.get('requested_by'), 128, 'requested_by'),
                   'requested_at': text(request.get('requested_at'), 20, 'requested_at')}
            clean = {'problems': problems, 'request': req, 'manifest': manifest(data.get('manifest'))}
            public = {'problems': [{'id': p['id'], 'title': p['title'], 'component': p['component'], 'kind': p['kind'],
                                    'result': 'pending'} for p in problems],
                      'revision': clean['manifest'].get('image_revision', ''), 'candidate_available': False,
                      'ready_to_apply': False}
            job = store.create_job(inst, clean, public)
            self.server.log({'event': 'job_created', 'installation': inst, 'job': job, 'problems': len(problems)})
            return 202, {'job': job, 'status': 'queued'}, None, 'application/json'
        if method == 'GET' and parts == ['jobs']:
            rows = [{'job': j['job'], 'status': j['status'], 'stage': j.get('stage', ''), 'created': j['created'],
                     'revision': j.get('candidate', {}).get('revision', j.get('revision', '')),
                     'candidate_available': j.get('candidate_available', False),
                     'problems': [p['title'] for p in j.get('problems', [])][:6]} for j in store.jobs_for(inst)]
            return 200, {'jobs': rows[:64]}, None, 'application/json'
        if len(parts) >= 2 and parts[0] == 'jobs' and JOB.match(parts[1]):
            record = store.job_for(inst, parts[1])
            if record is None:
                return 404, {'error': 'no_such_job'}, None, 'application/json'
            if method == 'GET' and len(parts) == 2:
                return 200, record['public'], None, 'application/json'
            if method == 'POST' and len(parts) == 3 and parts[2] == 'cancel':
                if record['public']['status'] not in ACTIVE:
                    return 409, {'error': 'not_running'}, None, 'application/json'
                store.update(parts[1], cancel_requested=True)
                if record['public']['status'] == 'queued':
                    store.update(parts[1], public={'status': 'cancelled', 'stage': 'cancelled before it started'})
                return 200, {'job': parts[1], 'cancel_requested': True}, None, 'application/json'
            if method == 'POST' and len(parts) == 3 and parts[2] == 'discard':
                if record['public']['status'] in ACTIVE:
                    return 409, {'error': 'still_running'}, None, 'application/json'
                store.update(parts[1], public={'status': 'discarded', 'ready_to_apply': False,
                                               'not_ready_reason': 'discarded by the user'})
                return 200, {'job': parts[1], 'status': 'discarded'}, None, 'application/json'
        return 404, {'error': 'not_found'}, None, 'application/json'

    # ---- deployment agents ----
    def agent_route(self, name, method, path, body):
        store = self.server.store
        agent = store.agent(name)
        parts = path.split('/')[4:]                 # after /merlin/v1/agent
        if len(parts) < 2 or parts[0] != 'jobs' or not JOB.match(parts[1]):
            return 404, {'error': 'not_found'}, None, 'application/json'
        try:
            record = store.load(parts[1])
        except (ValueError, OSError):
            return 404, {'error': 'no_such_job'}, None, 'application/json'
        if record['installation'] not in agent.get('installations', []):
            return 404, {'error': 'no_such_job'}, None, 'application/json'
        delta = store.job_dir(parts[1]) / 'delta'
        if method == 'GET' and len(parts) == 2:
            return 200, dict(record['public'], installation=record['installation']), None, 'application/json'
        if method == 'GET' and parts[2:] == ['delta', 'manifest']:
            if not (delta / 'manifest.json').exists():
                return 404, {'error': 'no_update_content'}, None, 'application/json'
            return 200, None, (delta / 'manifest.json').read_bytes(), 'application/json'
        if method == 'GET' and len(parts) == 5 and parts[2:4] == ['delta', 'files'] and parts[4].isdigit():
            m = json.loads((delta / 'manifest.json').read_text())
            index = int(parts[4])
            if index >= len(m['files']):
                return 404, {'error': 'no_such_file'}, None, 'application/json'
            return 200, None, (delta / 'files' / ('%03d.bin' % index)).read_bytes(), 'application/octet-stream'
        if method == 'POST' and parts[2:] == ['deployed']:
            data = json.loads(body)
            outcome = text(data.get('outcome'), 32, 'outcome', True)
            if outcome not in ('applied', 'rolled_back', 'failed_health_check', 'refused'):
                raise Invalid('outcome')
            detail = text(data.get('detail'), 512, 'detail')
            history = record['public'].get('deployment', []) + [{'time': now(), 'outcome': outcome, 'detail': detail, 'agent': name}]
            public = {'deployment': history[-20:]}
            if outcome == 'applied':
                public['status'] = 'applied'
            store.update(parts[1], public=public)
            return 200, {'recorded': True}, None, 'application/json'
        return 404, {'error': 'not_found'}, None, 'application/json'


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, store, limits, log_path=None):
        host, port = address
        self.address_family = socket.AF_INET6 if ':' in host else socket.AF_INET
        super().__init__(address, Handler)
        self.store, self.limits = store, limits
        self.challenges = protocol.Challenges()
        self.log_path = log_path

    def log(self, record):
        record = dict(record, time=now())
        line = json.dumps(record, sort_keys=True)
        if self.log_path:
            with open(self.log_path, 'a') as f:
                f.write(line + '\n')
        else:
            print(line, flush=True)


DEFAULT_LIMITS = {'max_request_bytes': 1024 * 1024, 'max_dump_bytes': 8 * 1024 * 1024, 'max_reports_per_installation': 500,
                  'installation_quota_bytes': 256 * 1024 * 1024, 'max_open_jobs_per_installation': 2}


def serve(config):
    limits = dict(DEFAULT_LIMITS, **config.get('limits', {}))
    store = Store(config['data'], limits)
    host, _, port = config.get('listen', '127.0.0.1:8740').rpartition(':')
    server = Server((host.strip('[]'), int(port)), store, limits, config.get('log'))
    server.log({'event': 'listening', 'address': config.get('listen')})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(serve(json.loads(Path(sys.argv[1]).read_text())))
