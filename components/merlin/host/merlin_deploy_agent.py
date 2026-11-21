#!/usr/bin/env python3
"""MerlinAI deployment agent: applies a tested MerlinAI update to an XP25 VM
on this host, only after the user approved it in the guest, and rolls back.

Guest API (XP25-MERLIN-DEPLOY1: HMAC with the installation's deployment key,
a key the builder never has, so a compromised builder cannot trigger a
deployment):
  GET  /deploy/v1/challenge
  GET  /deploy/v1/status                 current and previous system, history
  POST /deploy/v1/apply    {job, delta_sha256, approved_by, approved_at, statement}
  POST /deploy/v1/rollback {approved_by, approved_at, statement}
  POST /deploy/v1/health   {revision, winlogon_running, ...}  (MerlinSvc after every boot)

Apply, in order:
  1. authenticate the installation; one operation at a time (exclusive lock);
  2. fetch the job record from the builder with the agent's own credential; it
     must belong to this installation, be ready to apply, and name the same
     delta_sha256 the user approved;
  3. download the update content; SHA-256 of the manifest must equal
     delta_sha256 and every file must match its manifest hash; guest paths are
     restricted; the approval is journaled with the request's hash;
  4. answer 202; the guest shuts itself down (after 120 s the agent sends one
     ACPI power-button request); nothing happens to a running VM;
  5. keep the current disk unchanged: a new QCOW2 overlay on it receives the
     update offline, each file only if its installed SHA-256 is the expected
     one (otherwise the update is refused and the VM restarts unchanged);
  6. switch the domain's system disk to the overlay (only the disk source in
     the domain definition changes) and start it;
  7. wait for MerlinSvc's health report with the new revision (Winlogon, event
     log, RPC running, volume not dirty); if the VM does not start or does not
     report healthy, the agent restores the previous system and records the
     failure. A failed candidate is never deleted.
A replaced disk becomes read-only and is never booted directly again (the
newer image depends on it): rollback and restore start a fresh overlay on the
previous disk, so the newer image stays intact and can be returned to.
Before a guest is told to shut down, the agent checks that it can open disks
offline at all (the FUSE export needs the setuid fusermount3 helper).

The agent can start, stop and redefine only the domains in its configuration,
and creates files only in each installation's disk directory and its state
directory. It is honest about integrity: hashes and HMACs bind the update to
the approved job, but they do not make the builder trustworthy; a compromised
builder can still produce a malicious, correctly hashed update that the user
approves. See docs/merlinai-milestone9.md.

usage: merlin_deploy_agent.py --config agent.json
       merlin_deploy_agent.py --config agent.json adopt INSTALLATION [REVISION]   record the domain's current disk
       merlin_deploy_agent.py --config agent.json restore-current INSTALLATION    start a shut-off domain on the
                                                                                  last disk recorded as healthy"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
sys.path.insert(0, str(ROOT / 'vm'))
from merlin_builder import protocol  # noqa: E402

VIRSH = ['virsh', '-c', 'qemu:///system']
GUEST_PATH = re.compile(r'^/(WINDOWS|Program Files/XP25|xp25)/[A-Za-z0-9 ._/-]{1,200}$')
JOB = re.compile(r'^J-\d{8}-\d{6}-[0-9a-f]{6}$')


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


class Installation:
    def __init__(self, name, cfg, state_root):
        self.name = name
        self.key = bytes.fromhex(Path(cfg['deploy_key_file']).read_text().strip())
        self.domain = cfg['domain']
        self.disk_dir = Path(cfg['disk_dir']).resolve()
        self.client = cfg.get('client')
        self.dir = state_root / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.health = threading.Condition()
        self.last_health = None
        self.health_since = 0.0

    # ---- state ----
    def state(self):
        path = self.dir / 'state.json'
        return json.loads(path.read_text()) if path.exists() else {'operation': 'idle', 'history': []}

    def write_json(self, name, data):
        # A unique temporary file per write: the health handler and an operation's thread may write at once.
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix='.' + name + '.')
        with os.fdopen(fd, 'w') as f:
            f.write(json.dumps(data, indent=1) + '\n')
        os.replace(tmp, self.dir / name)

    def save(self, state):
        self.write_json('state.json', state)

    def reported_revision(self):
        """The revision the running system last reported (kept apart from state.json, which only the operation
        holding the installation's lock rewrites)."""
        path = self.dir / 'reported.json'
        return json.loads(path.read_text()).get('revision') if path.exists() else None

    def journal(self, **record):
        record['time'] = now()
        with (self.dir / 'journal.jsonl').open('a') as f:
            f.write(json.dumps(record, sort_keys=True) + '\n')

    # ---- libvirt, limited to this installation's domain ----
    def virsh(self, *args, check=True):
        r = subprocess.run(VIRSH + list(args), capture_output=True, text=True, timeout=120)
        self.journal(virsh=list(args), rc=r.returncode, stderr=r.stderr[-300:])
        if check and r.returncode:
            raise RuntimeError('virsh %s failed: %s' % (args[0], r.stderr.strip()[-200:]))
        return r.stdout

    def domstate(self):
        return self.virsh('domstate', self.domain).strip()

    def system_disk(self):
        xml = self.virsh('dumpxml', '--inactive', self.domain)
        m = re.search(r"<disk type='file' device='disk'>.*?<source file='([^']+)'.*?</disk>", xml, re.S)
        if not m:
            raise RuntimeError('no file-backed system disk in the domain')
        return Path(m.group(1)), xml

    def switch_disk(self, new):
        current, xml = self.system_disk()
        if Path(new).resolve().parent != self.disk_dir:
            raise RuntimeError('refusing a disk outside the installation directory')
        (self.dir / ('domain-%d.xml' % int(time.time()))).write_text(xml)
        changed = xml.replace("<source file='%s'" % current, "<source file='%s'" % new, 1)
        if changed == xml:
            raise RuntimeError('disk source not found in the domain definition')
        path = self.dir / 'domain-next.xml'
        path.write_text(changed)
        self.virsh('define', str(path))
        return current


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.state_root = Path(cfg['state']).resolve()
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.installations = {n: Installation(n, c, self.state_root) for n, c in cfg['installations'].items()}
        b = cfg['builder']
        self.builder = protocol.Client(b['url'], b['agent'], bytes.fromhex(Path(b['key_file']).read_text().strip()))
        self.challenges = protocol.Challenges()

    def key(self, name):
        inst = self.installations.get(name)
        return inst.key if inst else None

    # ---- apply ----
    def fetch_update(self, inst, request):
        job, delta_sha = request.get('job', ''), request.get('delta_sha256', '')
        if not JOB.match(job) or not protocol.HEX64.match(delta_sha):
            raise ValueError('job and delta_sha256 are required')
        status, data = self.builder.call('GET', '/agent/jobs/' + job)
        if status != 200:
            raise PermissionError('the builder does not show this job to this agent (%d)' % status)
        record = json.loads(data)
        if record.get('installation') != inst.name:
            raise PermissionError('the job belongs to another installation')
        if record.get('status') != 'ready' or not record.get('ready_to_apply'):
            raise PermissionError('the job is not ready to apply (%s)' % record.get('status'))
        if record.get('candidate', {}).get('delta_sha256') != delta_sha:
            raise PermissionError('the approved update is not the one the builder recorded for this job')
        status, manifest_bytes = self.builder.call('GET', '/agent/jobs/%s/delta/manifest' % job)
        if status != 200 or hashlib.sha256(manifest_bytes).hexdigest() != delta_sha:
            raise PermissionError('the update manifest does not match the approved hash')
        manifest = json.loads(manifest_bytes)
        if manifest.get('job') != job or manifest.get('installation') != inst.name:
            raise PermissionError('the update manifest names another job or installation')
        stage = inst.dir / 'stage' / job
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True)
        (stage / 'manifest.json').write_bytes(manifest_bytes)
        for i, f in enumerate(manifest['files']):
            if not GUEST_PATH.match(f.get('guest_path', '')) or '..' in f['guest_path'] or not protocol.HEX64.match(f.get('sha256', '')):
                raise PermissionError('the update names a guest path or hash the agent does not accept')
            status, content = self.builder.call('GET', '/agent/jobs/%s/delta/files/%d' % (job, i))
            if status != 200 or hashlib.sha256(content).hexdigest() != f['sha256']:
                raise PermissionError('update file %d does not match the manifest' % i)
            (stage / ('%03d.bin' % i)).write_bytes(content)
        return record, manifest, stage

    def offline_check(self, inst):
        """Prove that this agent can open a disk offline (the FUSE export that apply_offline uses) before any
        guest is asked to shut down. Returns None, or why it cannot (for example a unit with NoNewPrivileges,
        which disables the setuid fusermount3 helper)."""
        work = inst.dir / 'offline-check'
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir()
        disk, mount = work / 'probe.qcow2', work / 'probe.raw'
        try:
            subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', str(disk), '1M'], check=True, capture_output=True)
            mount.touch()
            node = json.dumps({'driver': 'qcow2', 'node-name': 'probe', 'file': {'driver': 'file', 'filename': str(disk)}})
            proc = subprocess.Popen(['qemu-storage-daemon', '--blockdev', node, '--export',
                                     'type=fuse,id=probe,node-name=probe,mountpoint=%s,writable=on,allow-other=off' % mount],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        return proc.stdout.read().decode(errors='replace').strip()[-300:] or 'the FUSE export failed'
                    if mount.stat().st_size:
                        break
                    time.sleep(.05)
                else:
                    return 'the FUSE export did not appear'
                r = subprocess.run(['fusermount', '-u', str(mount)], capture_output=True, text=True)
                if r.returncode:
                    return r.stderr.strip()[-300:] or 'fusermount -u failed'
                return None
            finally:
                proc.terminate()
                proc.wait(timeout=10)
        except (OSError, subprocess.CalledProcessError) as e:
            return str(e)[-300:]
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def apply_offline(self, inst, base, overlay, manifest, stage):
        import xp_lab as lab
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(overlay)], check=True)
        work = inst.dir / ('offline-%d' % int(time.time()))
        work.mkdir()
        cwd = os.getcwd()
        os.chdir(work)
        applied = []
        try:
            with lab.partition(overlay, True) as device:
                for i, f in enumerate(manifest['files']):
                    try:
                        before = lab.run(['ntfscat', device, f['guest_path']])
                    except RuntimeError:
                        before = None
                    found = hashlib.sha256(before).hexdigest() if before is not None else None
                    if found != f.get('expected_before'):
                        raise PermissionError('%s on this computer is not the expected one (%s); the update was not made for it'
                                              % (f['guest_path'], (found or 'absent')[:16]))
                for i, f in enumerate(manifest['files']):
                    lab.run(['ntfscp', device, str(stage / ('%03d.bin' % i)), f['guest_path']])
                    after = lab.run(['ntfscat', device, f['guest_path']])
                    if hashlib.sha256(after).hexdigest() != f['sha256']:
                        raise RuntimeError('offline replacement of %s did not take effect' % f['guest_path'])
                    applied.append(f['guest_path'])
        finally:
            os.chdir(cwd)
        subprocess.run(['qemu-img', 'check', '-q', str(overlay)], check=True)
        return applied

    def overlay_on(self, inst, base, label):
        """A new, empty top image on base. A disk that another image depends on is never booted or written
        again: rollback and restore start a fresh overlay on it, so the newer image stays valid."""
        target = inst.disk_dir / ('%s.%s.qcow2' % (inst.domain, label))
        n = 1
        while target.exists():
            n += 1
            target = inst.disk_dir / ('%s.%s.%d.qcow2' % (inst.domain, label, n))
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(target)], check=True)
        return target

    def wait_shutdown(self, inst, timeout):
        deadline, acpi_sent = time.time() + timeout, False
        started = time.time()
        while time.time() < deadline:
            if inst.domstate() == 'shut off':
                return True
            if not acpi_sent and time.time() - started > 120:
                inst.virsh('shutdown', inst.domain, check=False)
                acpi_sent = True
            time.sleep(5)
        return False

    def wait_health(self, inst, revision, timeout):
        deadline = time.time() + timeout
        with inst.health:
            while time.time() < deadline:
                h = inst.last_health
                if h and h['received'] > inst.health_since and (revision == 'unrecorded' or h['report'].get('revision') == revision):
                    r = h['report']
                    ok = all(r.get(k) is True for k in ('winlogon_running', 'eventlog_running', 'rpc_running')) and \
                        r.get('volume_dirty') in (0, 2)
                    return ok, r
                inst.health.wait(timeout=10)
        return False, None

    def deploy(self, inst, target, revision, operation, approval, job=None):
        """Switch the domain to target, start it, require a healthy report, else restore."""
        timeout = int(self.cfg.get('health_timeout_seconds', 900))
        state = inst.state()
        # The system being replaced: as recorded by an earlier deployment, else as it last reported itself
        # (an enrolled VM's first image was never deployed by the agent).
        prior_revision = (state.get('current') or {}).get('revision') or inst.reported_revision() or 'unrecorded'
        previous_disk = inst.switch_disk(target)
        try:
            os.chmod(previous_disk, 0o444)               # replaced: kept for rollback, never written again
        except OSError as e:
            inst.journal(event='replaced_disk_not_read_only', disk=str(previous_disk), error=str(e))
        inst.health_since = time.time()
        state.update(operation='waiting_for_health', target=str(target), expected_revision=revision)
        inst.save(state)
        try:
            inst.virsh('start', inst.domain)
        except RuntimeError as e:
            inst.journal(event=operation + '_start_failed', disk=str(target), error=str(e)[-300:])
            healthy, report = False, None
        else:
            healthy, report = self.wait_health(inst, revision, timeout)
        state = inst.state()
        if healthy:
            entry = {'time': now(), 'operation': operation, 'outcome': 'healthy', 'disk': str(target), 'revision': revision,
                     'replaced': str(previous_disk), 'job': job, 'approval': approval}
            state['history'] = (state.get('history') or []) + [entry]
            state['previous'] = {'disk': str(previous_disk), 'revision': prior_revision}
            state['current'] = {'disk': str(target), 'revision': revision, 'since': now()}
            state.pop('last_refusal', None)              # shown in the guest until an operation succeeds
            state['operation'] = 'idle'
            inst.save(state)
            inst.journal(event=operation + '_healthy', disk=str(target), revision=revision, report=report)
            return True
        inst.journal(event=operation + '_unhealthy', disk=str(target), revision=revision, report=report)
        inst.virsh('destroy', inst.domain, check=False)
        for _ in range(60):
            if inst.domstate() == 'shut off':
                break
            time.sleep(2)
        restore = self.overlay_on(inst, previous_disk, 'restored')
        inst.switch_disk(restore)
        inst.virsh('start', inst.domain)
        entry = {'time': now(), 'operation': operation, 'outcome': 'restored_previous_after_failed_health_check',
                 'failed_disk': str(target), 'restored_from': str(previous_disk), 'restored_disk': str(restore), 'job': job,
                 'report': report}
        state['history'] = (state.get('history') or []) + [entry]
        state['current'] = {'disk': str(restore), 'revision': prior_revision, 'since': now()}
        state['operation'] = 'idle'
        inst.save(state)
        inst.journal(event=operation + '_restored_previous', restored_disk=str(restore), backing=str(previous_disk))
        return False

    def run_apply(self, inst, request, approval_hash):
        job = request['job']
        try:
            record, manifest, stage = self.fetch_update(inst, request)
        except (PermissionError, ValueError, ConnectionError, OSError) as e:
            inst.journal(event='apply_refused', job=job, reason=str(e))
            st = inst.state()
            st['operation'] = 'idle'
            st['last_refusal'] = {'time': now(), 'job': job, 'reason': str(e)}
            inst.save(st)
            return
        inst.journal(event='apply_staged', job=job, delta_sha256=request['delta_sha256'], approval_sha256=approval_hash,
                     approved_by=request.get('approved_by'), approved_at=request.get('approved_at'), files=len(manifest['files']))
        st = inst.state()
        st['operation'] = 'waiting_for_shutdown'
        inst.save(st)
        if not self.wait_shutdown(inst, int(self.cfg.get('shutdown_timeout_seconds', 600))):
            inst.journal(event='apply_cancelled', job=job, reason='the guest did not shut down; nothing was changed')
            st = inst.state()
            st['operation'] = 'idle'
            inst.save(st)
            return
        current, _ = inst.system_disk()
        overlay = inst.disk_dir / ('%s.%s.qcow2' % (inst.domain, job))
        attempt = 1
        while overlay.exists():                          # an earlier attempt's overlay is evidence: never overwritten
            attempt += 1
            overlay = inst.disk_dir / ('%s.%s.%d.qcow2' % (inst.domain, job, attempt))
        st = inst.state()
        st['operation'] = 'applying'
        inst.save(st)
        try:
            applied = self.apply_offline(inst, current, overlay, manifest, stage)
        except (PermissionError, RuntimeError, subprocess.CalledProcessError, OSError) as e:
            inst.journal(event='apply_refused_offline', job=job, reason=str(e))
            inst.virsh('start', inst.domain, check=False)
            st = inst.state()
            st.update(operation='idle', last_refusal={'time': now(), 'job': job, 'reason': str(e)})
            inst.save(st)
            self.report(job, 'refused', str(e))
            return
        os.chmod(current, 0o444)                         # now a backing file: never written again
        inst.journal(event='apply_written', job=job, overlay=str(overlay), base=str(current), files=applied)
        ok = self.deploy(inst, overlay, manifest['revision'], 'apply', {'by': request.get('approved_by'), 'at': request.get('approved_at'),
                                                                       'sha256': approval_hash}, job)
        self.report(job, 'applied' if ok else 'failed_health_check',
                    'healthy' if ok else 'no healthy report; the previous system image was restored')

    def run_rollback(self, inst, request, approval_hash):
        st = inst.state()
        previous = st.get('previous')
        if not previous:
            inst.journal(event='rollback_refused', reason='no previous system recorded')
            st['operation'] = 'idle'
            inst.save(st)
            return
        st['operation'] = 'waiting_for_shutdown'
        inst.save(st)
        if not self.wait_shutdown(inst, int(self.cfg.get('shutdown_timeout_seconds', 600))):
            inst.journal(event='rollback_cancelled', reason='the guest did not shut down')
            st = inst.state()
            st['operation'] = 'idle'
            inst.save(st)
            return
        target = self.overlay_on(inst, Path(previous['disk']), 'rollback')
        inst.journal(event='rollback_started', to=previous['disk'], overlay=str(target), approval_sha256=approval_hash)
        self.deploy(inst, target, previous['revision'] or 'unrecorded', 'rollback',
                    {'by': request.get('approved_by'), 'at': request.get('approved_at'), 'sha256': approval_hash})

    def report(self, job, outcome, detail):
        try:
            self.builder.call('POST', '/agent/jobs/%s/deployed' % job, json.dumps({'outcome': outcome, 'detail': detail[:500]}).encode())
        except (ConnectionError, PermissionError, OSError) as e:
            print(json.dumps({'event': 'builder_report_failed', 'error': str(e)}), flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'MerlinAI-Deploy/1'
    sys_version = ''

    def log_message(self, *args):
        pass

    def send(self, status, data, key=None, nonce=None):
        body = json.dumps(data, sort_keys=True).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        if key:
            self.send_header('X-Merlin-Signature', protocol.sign_response(protocol.LABEL_DEPLOY, key, nonce, status, body))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def handle_any(self, method):
        agent = self.server.agent
        if self.path == '/deploy/v1/challenge' and method == 'GET':
            return self.send(200, {'challenge': agent.challenges.issue()})
        length = self.headers.get('Content-Length', '0')
        if method == 'POST' and (not length.isdigit() or int(length) > 65536):
            return self.send(413, {'error': 'request_too_large'})
        body = self.rfile.read(int(length)) if method == 'POST' else b''
        try:
            name, nonce, key = protocol.check_request(protocol.LABEL_DEPLOY, agent.key, agent.challenges, method, self.path, self.headers, body)
        except PermissionError as e:
            print(json.dumps({'event': 'unauthenticated', 'client': self.client_address[0], 'reason': str(e), 'time': now()}), flush=True)
            return self.send(401, {'error': str(e)})
        inst = agent.installations[name]
        if inst.client and self.client_address[0] != inst.client:
            return self.send(403, {'error': 'wrong_client_address'}, key, nonce)
        if method == 'GET' and self.path == '/deploy/v1/status':
            st = inst.state()
            previous = st.get('previous') or {}
            return self.send(200, {'state': st.get('operation', 'idle'), 'current': st.get('current', {}).get('revision', ''),
                                   'previous': previous.get('revision') or ('unrecorded revision' if previous.get('disk') else ''),
                                   'history': [{k: h.get(k) for k in ('time', 'operation', 'outcome', 'revision', 'job')}
                                               for h in st.get('history', [])][-10:],
                                   'last_refusal': st.get('last_refusal')}, key, nonce)
        if method == 'POST' and self.path == '/deploy/v1/health':
            try:
                report = json.loads(body)
            except ValueError:
                return self.send(400, {'error': 'invalid_json'}, key, nonce)
            with inst.health:
                inst.last_health = {'received': time.time(), 'report': report}
                inst.health.notify_all()
            inst.journal(event='health_report', report=report)
            if isinstance(report, dict) and isinstance(report.get('revision'), str) and report['revision']:
                inst.write_json('reported.json', {'revision': report['revision'][:120], 'time': now()})
            return self.send(200, {'recorded': True}, key, nonce)
        if method == 'POST' and self.path in ('/deploy/v1/apply', '/deploy/v1/rollback'):
            try:
                request = json.loads(body)
            except ValueError:
                return self.send(400, {'error': 'invalid_json'}, key, nonce)
            if not isinstance(request, dict) or not request.get('approved_by') or not request.get('statement'):
                return self.send(400, {'error': 'explicit_approval_required'}, key, nonce)
            if not inst.lock.acquire(blocking=False) or inst.state().get('operation', 'idle') != 'idle':
                return self.send(409, {'error': 'another_operation_in_progress'}, key, nonce)
            approval_hash = hashlib.sha256(body).hexdigest()
            st = inst.state()
            st['operation'] = 'staging'
            inst.save(st)
            inst.journal(event='approval_received', path=self.path, approval_sha256=approval_hash, approval=request)

            def work():
                try:
                    if self.path.endswith('/apply'):
                        agent.run_apply(inst, request, approval_hash)
                    else:
                        agent.run_rollback(inst, request, approval_hash)
                except Exception as e:                     # recorded, never silent
                    inst.journal(event='operation_error', error=repr(e)[:500])
                    st2 = inst.state()
                    st2['operation'] = 'idle'
                    inst.save(st2)
                finally:
                    inst.lock.release()
            if self.path.endswith('/apply'):
                # Prove offline application works and validate against the builder before telling the guest to shut down.
                try:
                    problem = agent.offline_check(inst)
                    if problem:
                        raise PermissionError('offline application is unavailable on this host: ' + problem)
                    agent.fetch_update(inst, request)
                except (PermissionError, ValueError, ConnectionError, OSError) as e:
                    st = inst.state()
                    st.update(operation='idle', last_refusal={'time': now(), 'job': request.get('job'), 'reason': str(e)})
                    inst.save(st)
                    inst.lock.release()
                    inst.journal(event='apply_refused', reason=str(e))
                    return self.send(409, {'error': 'update_refused', 'detail': str(e)[:300]}, key, nonce)
            threading.Thread(target=work, daemon=True).start()
            return self.send(202, {'accepted': True, 'next': 'shut Windows down; the agent switches the system image'}, key, nonce)
        return self.send(404, {'error': 'not_found'}, key, nonce)

    def do_GET(self):
        self.handle_any('GET')

    def do_POST(self):
        self.handle_any('POST')


def recover_previous_revision(inst):
    """State written before the agent recorded reported revisions can name a previous disk without its revision.
    Recover it from this agent's own journal: the last health report before that disk was replaced."""
    st = inst.state()
    previous = st.get('previous') or {}
    path = inst.dir / 'journal.jsonl'
    if not previous.get('disk') or previous.get('revision') or not path.exists():
        return
    revision = None
    for line in path.read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get('event') == 'health_report' and isinstance(e.get('report'), dict):
            revision = e['report'].get('revision') or revision
        elif e.get('event') == 'apply_written' and e.get('base') == previous['disk']:
            break
    else:
        return
    if revision:
        previous['revision'] = revision[:120]
        st['previous'] = previous
        inst.save(st)
        inst.journal(event='previous_revision_recovered', disk=previous['disk'], revision=previous['revision'],
                     source='last health report before the disk was replaced')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('command', nargs='*')
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    agent = Agent(cfg)
    if args.command[:1] == ['restore-current']:
        # Operator recovery: start the domain again on the disk the agent last recorded as healthy.
        inst = agent.installations[args.command[1]]
        st = inst.state()
        if st.get('operation', 'idle') != 'idle' or inst.domstate() != 'shut off' or not (st.get('current') or {}).get('disk'):
            raise SystemExit('restore-current needs an idle installation, a shut-off domain and a recorded current disk')
        disk, _ = inst.system_disk()
        if str(disk) != st['current']['disk']:
            inst.switch_disk(st['current']['disk'])
        inst.virsh('start', inst.domain)
        inst.journal(event='operator_restored_current', disk=st['current']['disk'], defined_disk_was=str(disk))
        print(json.dumps({'started': st['current']}))
        return 0
    if args.command[:1] == ['adopt']:
        inst = agent.installations[args.command[1]]
        disk, _ = inst.system_disk()
        st = inst.state()
        st['current'] = {'disk': str(disk), 'revision': args.command[2] if len(args.command) > 2 else '', 'since': now()}
        inst.save(st)
        print(json.dumps(st['current']))
        return 0
    host, _, port = cfg['listen'].rpartition(':')
    import socket

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def server_bind(self):
            if cfg.get('freebind') and hasattr(socket, 'IP_FREEBIND'):
                self.socket.setsockopt(socket.SOL_IP, socket.IP_FREEBIND, 1)
            super().server_bind()
    server = Server((host, int(port)), Handler)
    server.agent = agent
    for inst in agent.installations.values():
        st = inst.state()
        if st.get('operation', 'idle') != 'idle':
            inst.journal(event='agent_restarted_during_operation', operation=st['operation'])
            st['operation'] = 'idle'
            inst.save(st)
        recover_previous_revision(inst)
    first = next(iter(agent.installations.values()), None)
    offline = agent.offline_check(first) if first else 'no installations'
    print(json.dumps({'event': 'listening', 'listen': cfg['listen'], 'installations': sorted(agent.installations),
                      'offline_application': offline or 'available'}), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    sys.exit(main())
