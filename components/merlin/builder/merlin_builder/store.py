"""Builder state on disk: installations, their reports, build jobs and
deployment-agent credentials.

  <data>/installations/<id>/installation.json   key and quotas (mode 0600)
  <data>/installations/<id>/reports/<P-id>.json  transferred reports (untrusted input)
  <data>/installations/<id>/reports/<P-id>.dmp   consented memory dumps
  <data>/agents/<name>.json                      deployment-agent key and the installations it serves
  <data>/jobs/<J-id>/job.json                    the job record (public part under "public")
  <data>/jobs/<J-id>/request.json                the build request as received (untrusted input)

Every read for a client goes through the installation that authenticated, so
one installation can never see or change another's reports or jobs. Writes
are atomic (temporary file + rename) and serialized per job with flock."""
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import secrets

INSTALLATION = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
JOB = re.compile(r'^J-\d{8}-\d{6}-[0-9a-f]{6}$')
PROBLEM = re.compile(r'^[PC]-[0-9a-f]{16}$')
ACTIVE = ('queued', 'investigating', 'building', 'packaging', 'testing')
TERMINAL = ('ready', 'no_change', 'failed', 'cancelled', 'discarded', 'applied')


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def write_json(path: Path, data, mode=0o640):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp-' + secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class Store:
    def __init__(self, root, limits):
        self.root = Path(root)
        self.limits = limits
        for name in ('installations', 'jobs', 'agents'):
            (self.root / name).mkdir(parents=True, exist_ok=True, mode=0o750)

    # ---- installations and agents ----
    def installation_dir(self, inst):
        if not INSTALLATION.match(inst or ''):
            raise ValueError('bad installation id')
        return self.root / 'installations' / inst

    def register_installation(self, inst, baseline, description=''):
        d = self.installation_dir(inst)
        d.mkdir(mode=0o700)
        (d / 'reports').mkdir(mode=0o700)
        key = secrets.token_hex(32)
        write_json(d / 'installation.json', {'id': inst, 'key_hex': key, 'baseline': baseline, 'description': description,
                                             'created': now(), 'enabled': True}, mode=0o600)
        return key

    def installation(self, inst):
        try:
            data = json.loads((self.installation_dir(inst) / 'installation.json').read_text())
        except (ValueError, OSError):
            return None
        return data if data.get('enabled') else None

    def key(self, inst):
        data = self.installation(inst)
        return bytes.fromhex(data['key_hex']) if data else None

    def register_agent(self, name, installations):
        if not INSTALLATION.match(name or ''):
            raise ValueError('bad agent name')
        path = self.root / 'agents' / (name + '.json')
        if path.exists():
            raise FileExistsError(name)
        key = secrets.token_hex(32)
        write_json(path, {'name': name, 'key_hex': key, 'installations': sorted(installations), 'created': now()}, mode=0o600)
        return key

    def agent(self, name):
        if not INSTALLATION.match(name or ''):
            return None
        try:
            return json.loads((self.root / 'agents' / (name + '.json')).read_text())
        except (ValueError, OSError):
            return None

    def agent_key(self, name):
        data = self.agent(name)
        return bytes.fromhex(data['key_hex']) if data else None

    # ---- reports ----
    def save_reports(self, inst, problems):
        d = self.installation_dir(inst) / 'reports'
        existing = len(list(d.glob('*.json')))
        accepted = []
        for p in problems:
            path = d / (p['id'] + '.json')
            if not path.exists() and existing >= self.limits['max_reports_per_installation']:
                break
            if not path.exists():
                existing += 1
            write_json(path, {'received': now(), 'untrusted': True, 'problem': p})
            accepted.append(p['id'])
        return accepted

    def installation_bytes(self, inst):
        return sum(f.stat().st_size for f in self.installation_dir(inst).rglob('*') if f.is_file())

    def save_dump(self, inst, problem_id, data):
        if not PROBLEM.match(problem_id):
            raise ValueError('bad problem id')
        d = self.installation_dir(inst) / 'reports'
        if not (d / (problem_id + '.json')).exists():
            raise FileNotFoundError(problem_id)
        if self.installation_bytes(inst) + len(data) > self.limits['installation_quota_bytes']:
            raise OverflowError('installation storage quota')
        tmp = d / (problem_id + '.dmp.tmp')
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, d / (problem_id + '.dmp'))

    def report(self, inst, problem_id):
        try:
            return json.loads((self.installation_dir(inst) / 'reports' / (problem_id + '.json')).read_text())
        except (ValueError, OSError):
            return None

    # ---- jobs ----
    def job_dir(self, job):
        if not JOB.match(job or ''):
            raise ValueError('bad job id')
        return self.root / 'jobs' / job

    @contextlib.contextmanager
    def locked(self, job):
        d = self.job_dir(job)
        with open(d / '.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield d

    def create_job(self, inst, request, public):
        open_jobs = [j for j in self.jobs_for(inst) if j['status'] in ACTIVE]
        if len(open_jobs) >= self.limits['max_open_jobs_per_installation']:
            raise OverflowError('too many open build jobs for this installation')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
        job = 'J-%s-%s' % (stamp, secrets.token_hex(3))
        d = self.job_dir(job)
        d.mkdir(mode=0o750)
        write_json(d / 'request.json', {'received': now(), 'untrusted': True, 'installation': inst, 'request': request})
        record = {'installation': inst, 'cancel_requested': False, 'internal': {},
                  'public': dict(public, job=job, status='queued', stage='waiting for the builder', created=now(), updated=now())}
        write_json(d / 'job.json', record)
        return job

    def load(self, job):
        return json.loads((self.job_dir(job) / 'job.json').read_text())

    def update(self, job, public=None, internal=None, **fields):
        with self.locked(job) as d:
            record = json.loads((d / 'job.json').read_text())
            if public:
                record['public'].update(public)
                record['public']['updated'] = now()
            if internal:
                record['internal'].update(internal)
            record.update(fields)
            write_json(d / 'job.json', record)
            return record

    def job_for(self, inst, job):
        """The job record if it belongs to inst, else None (never reveals another installation's job)."""
        try:
            record = self.load(job)
        except (ValueError, OSError):
            return None
        return record if record.get('installation') == inst else None

    def jobs_for(self, inst):
        rows = []
        for d in sorted((self.root / 'jobs').glob('J-*'), reverse=True):
            try:
                record = json.loads((d / 'job.json').read_text())
            except (ValueError, OSError):
                continue
            if record.get('installation') == inst:
                rows.append(record['public'])
        return rows

    def all_jobs(self):
        for d in sorted((self.root / 'jobs').glob('J-*')):
            try:
                yield d.name, json.loads((d / 'job.json').read_text())
            except (ValueError, OSError):
                continue
