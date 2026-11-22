"""MerlinAI build pipeline for one job (the execution plane).

  workspace    a fresh clone of the immutable baseline repository at the
               approved commit, for this job alone
  investigate  model or offline investigator (merlin_builder.investigate)
  checks       MinGW cross-compile of the changed component, no network
  native       the NT 5.1 toolchain build in a disposable clone of the build VM
  assemble     candidate image: a QCOW2 overlay of the installation's baseline
               with only the rebuilt binaries replaced offline, plus the
               update content (delta) and its manifest
  test         disposable overlays: the reported problem before (baseline) and
               after (candidate), and a boot/logon/shutdown regression, per mode
  publish      results per problem, readiness, limitations

Every step records itself in <job>/steps.jsonl. A failure stops the job and
keeps all evidence. The baseline repository, baseline image and build image
are only ever read. Nothing a report contains is executed: tests run fixed
commands from the component map, never text from a report."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from . import investigate as inv
from .store import now

PIPELINE_VERSION = 1


class Cancelled(Exception):
    pass


class StepFailed(Exception):
    pass


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


class Job:
    def __init__(self, config, store, job):
        self.config, self.store, self.job = config, store, job
        self.dir = store.job_dir(job)
        self.record = store.load(job)
        self.installation = store.installation(self.record['installation'])
        self.baseline_name = self.installation['baseline']
        self.baseline = config['baselines'][self.baseline_name]
        self.request = json.loads((self.dir / 'request.json').read_text())['request']
        self.tools = Path(config['tools']).resolve()          # repository checkout with build/ and vm/
        self.processes = []

    # ---- bookkeeping ----
    def log(self, step, **data):
        with (self.dir / 'steps.jsonl').open('a') as f:
            f.write(json.dumps(dict(data, step=step, time=now()), sort_keys=True) + '\n')

    def stage(self, status, stage):
        self.check_cancel()
        self.store.update(self.job, public={'status': status, 'stage': stage})
        self.log('stage', status=status, stage=stage)

    def check_cancel(self):
        if self.store.load(self.job).get('cancel_requested'):
            raise Cancelled()

    def run(self, argv, step, timeout, cwd=None, env=None, sandbox=True):
        """Run a fixed tool with a time limit; output goes to logs/<step>.log. No shell.
        sandbox: run it in a new user and network namespace (no network at all). Steps that
        export disk images over FUSE run unsandboxed; their QEMU guests have no NIC."""
        logs = self.dir / 'logs'
        logs.mkdir(exist_ok=True)
        if sandbox and shutil.which('unshare') and self.config.get('sandbox_network', True):
            argv = ['unshare', '--user', '--map-root-user', '--net'] + [str(a) for a in argv]
        with (logs / (step + '.log')).open('ab') as out:
            out.write(('\n$ %s\n' % ' '.join(str(a) for a in argv)).encode())
            out.flush()
            p = subprocess.Popen([str(a) for a in argv], stdout=out, stderr=subprocess.STDOUT, cwd=cwd, env=env,
                                 start_new_session=True)
            self.processes.append(p)
            deadline = time.time() + timeout
            while p.poll() is None:
                if time.time() > deadline:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
                    raise StepFailed('%s timed out after %d s' % (step, timeout))
                if self.store.load(self.job).get('cancel_requested'):
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
                    raise Cancelled()
                time.sleep(2)
            self.processes.remove(p)
            return p.returncode

    # ---- steps ----
    def workspace(self):
        self.stage('investigating', 'preparing an isolated source workspace')
        ws = self.dir / 'workspace'
        repo, commit = self.baseline['repository'], self.baseline['commit']
        r = subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', repo, str(ws)], capture_output=True, text=True)
        if r.returncode:
            raise StepFailed('workspace clone failed: ' + r.stderr[-300:])
        r = subprocess.run(['git', '-C', str(ws), 'checkout', '--quiet', '-b', 'merlin-' + self.job, commit], capture_output=True, text=True)
        head = subprocess.run(['git', '-C', str(ws), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        if r.returncode or head != commit:
            raise StepFailed('the approved baseline commit is not available: ' + r.stderr[-300:])
        self.log('workspace', commit=head)
        return ws

    def investigate(self, ws):
        self.stage('investigating', 'investigating the reported problems')
        workspace = inv.Workspace(ws)
        symbols = self.baseline.get('symbols')
        provider_config = self.config.get('provider') or {'kind': 'offline'}
        kind = provider_config.get('kind', 'offline')

        def tool_log(entry):
            with (self.dir / 'investigation-tools.jsonl').open('a') as f:
                f.write(json.dumps(entry) + '\n')
        if kind in inv.PROVIDERS:
            key = Path(provider_config['key_file']).read_text().strip()
            provider = inv.PROVIDERS[kind](provider_config, key)
            investigator = inv.ModelInvestigator(provider, workspace, symbols, compile_check=lambda: self.compile_check(ws, quiet=True),
                                                 log=tool_log, max_steps=int(provider_config.get('max_steps', 30)))
        else:
            investigator = inv.OfflineInvestigator(workspace, symbols, log=tool_log)
        try:
            analysis = investigator.investigate(self.request['problems'])
        except inv.ProviderError as e:
            raise StepFailed('the model provider failed: %s' % str(e)[:300])
        analysis['diff'] = workspace.diff()
        (self.dir / 'analysis.json').write_text(json.dumps(analysis, indent=1) + '\n')
        (self.dir / 'changes.diff').write_text(analysis['diff'])
        self.log('investigate', investigator=analysis['investigator'], edits=len(analysis['edits']))
        return analysis

    def changed_targets(self, ws, analysis):
        """Binaries (from the component map) whose source directories the edits touched."""
        table = inv.load_components()
        files = sorted({e['file'] for e in analysis['edits']})
        targets = {}
        for f in files:
            for name, info in table['binaries'].items():
                # Only components the builder rebuilds natively (build "merlin") become candidate files.
                if info.get('build') == 'merlin' and f.startswith(info['source'].rstrip('/') + '/'):
                    targets[info['target']] = info
        return files, targets

    def compile_check(self, ws, quiet=False):
        out = ws / '.work' / ('mingw-check-%d' % int(time.time() * 1000))     # the workspace's own .work, as its tools require
        code = self.run([sys.executable, ws / 'build/merlin_build.py', '--toolchain', self.config['toolchain'], '--output', out,
                         '--guest-modules', self.baseline['guest_modules']], 'compile-check', 900, cwd=ws)
        result = json.loads((out / 'result.json').read_text()) if (out / 'result.json').exists() else {'status': 'no result'}
        if quiet:
            return json.dumps({'status': result.get('status'), 'error': result.get('error', '')[-1500:]})
        return result

    def native(self, ws):
        self.stage('building', 'building the changed components with the NT 5.1 toolchain')
        # The native build driver accepts media only under the tools' own .work (as for every lab tool).
        media = self.tools / '.work' / 'merlin-jobs' / self.job / 'native-media'
        media.parent.mkdir(parents=True, exist_ok=True)
        code = self.run([sys.executable, self.tools / 'build/prepare_merlin.py', '--output', media, '--source', ws], 'native-media', 300,
                        sandbox=False)
        if code:
            raise StepFailed('native build media could not be prepared')
        name = 'merlin-' + self.job.lower()
        code = self.run([sys.executable, self.tools / 'vm/merlin_native_build.py', '--media', media, '--name', name,
                         '--base', self.baseline['build_vm'], '--guest-modules', self.baseline['guest_modules'],
                         '--toolchain', self.config['toolchain']], 'native-build', int(self.config.get('native_timeout', 3600)),
                        sandbox=False)
        collect = self.tools / '.work/boot-debug-20261022' / name / 'collect'
        record = json.loads((collect / 'collect.json').read_text()) if (collect / 'collect.json').exists() else None
        if code or not record or record.get('status') != 'accepted':
            raise StepFailed('the native build failed: %s' % ((record or {}).get('problems') or 'no collection'))
        self.log('native', collection=str(collect), binaries={k: v['sha256'] for k, v in record['binaries'].items()})
        return collect

    def assemble(self, collect, targets):
        self.stage('packaging', 'assembling the candidate system image')
        image_dir = self.dir / 'image'
        image_dir.mkdir()
        base = Path(self.baseline['image'])
        candidate = image_dir / 'candidate.qcow2'
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', self.baseline.get('image_format', 'qcow2'), '-b', str(base),
                        str(candidate)], check=True)
        sys.path.insert(0, str(self.tools / 'vm'))
        import xp_lab as lab
        delta = self.dir / 'delta'
        (delta / 'files').mkdir(parents=True)
        revision = '%s+%s' % (self.baseline.get('revision', self.baseline_name), self.job)
        revision_file = image_dir / 'image-revision.txt'
        revision_file.write_bytes((revision + '\r\n').encode())
        files = []
        cwd = os.getcwd()
        os.chdir(image_dir)
        try:
            with lab.partition(candidate, True) as device:
                for name, info in sorted(targets.items()):
                    new = collect / 'build' / info['target']
                    before = lab.run(['ntfscat', device, info['guest_path']])
                    lab.run(['ntfscp', device, str(new), info['guest_path']])
                    after = lab.run(['ntfscat', device, info['guest_path']])
                    if hashlib.sha256(after).hexdigest() != sha(new):
                        raise StepFailed('offline replacement of %s did not take effect' % info['guest_path'])
                    files.append({'guest_path': info['guest_path'], 'sha256': sha(new), 'bytes': new.stat().st_size,
                                  'expected_before': hashlib.sha256(before).hexdigest(), 'component': info['target']})
                # Files are only replaced offline, never created: a file written by ntfscp gets no security
                # descriptor, so it would be writable by every account. The baseline must carry the revision file.
                try:
                    old_revision = lab.run(['ntfscat', device, '/xp25/image-revision.txt'])
                except RuntimeError:
                    raise StepFailed('the baseline image has no C:\\xp25\\image-revision.txt; a new file cannot be created '
                                     'offline with access control')
                lab.run(['ntfscp', device, str(revision_file), '/xp25/image-revision.txt'])
                files.append({'guest_path': '/xp25/image-revision.txt', 'sha256': sha(revision_file), 'bytes': revision_file.stat().st_size,
                              'expected_before': hashlib.sha256(old_revision).hexdigest(),
                              'component': 'image revision'})
        finally:
            os.chdir(cwd)
        for i, f in enumerate(files):
            source = (collect / 'build' / f['component']) if f['component'] != 'image revision' else revision_file
            shutil.copy2(source, delta / 'files' / ('%03d.bin' % i))
        manifest = {'schema': 'xp25-merlin-delta/1', 'job': self.job, 'installation': self.record['installation'],
                    'baseline': self.baseline_name, 'baseline_image_sha256': self.baseline['image_sha256'],
                    'source_commit': self.baseline['commit'], 'revision': revision, 'files': files}
        text = json.dumps(manifest, indent=1, sort_keys=True) + '\n'
        (delta / 'manifest.json').write_text(text)
        delta_sha = hashlib.sha256(text.encode()).hexdigest()
        subprocess.run(['qemu-img', 'check', '-q', str(candidate)], check=True)
        candidate.chmod(0o444)
        image_sha = sha(candidate)
        self.log('assemble', candidate=str(candidate), image_sha256=image_sha, delta_sha256=delta_sha, files=len(files))
        return {'image': str(candidate), 'sha256': image_sha, 'delta_sha256': delta_sha, 'revision': revision, 'files': files,
                'base': '%s (%s)' % (self.baseline_name, self.baseline['image_sha256'][:16])}

    def test(self, candidate, targets, analysis):
        self.stage('testing', 'testing the candidate image')
        results = []
        modes = self.config.get('test_modes', ['up'])
        repro = [(info['target'], info['reproduce']) for info in targets.values() if info.get('reproduce')]
        for mode in modes:
            for label, image in (('before', self.baseline['image']), ('after', candidate['image'])):
                if label == 'before' and mode != modes[0]:
                    continue                                  # the defect is shown once, on the baseline
                run = '%s-%s-%s' % (self.job.lower(), label, mode)
                checks = [r[1]['command'] for r in repro]
                extra = ['--mp-kernel', self.baseline['mp_kernel'], '--mp-hal', self.baseline['mp_hal']] if mode == 'mp' else []
                code = self.run([sys.executable, self.tools / 'vm/merlin_jobtest.py', '--name', run, '--mode', mode,
                                 '--image', image, '--checks', json.dumps(checks), '--runs', self.dir / 'tests'] + extra,
                                'test-%s-%s' % (label, mode), int(self.config.get('test_timeout', 2700)) * (3 if mode == 'tcg' else 1),
                                sandbox=False)
                result_path = self.dir / 'tests' / run / 'results.json'
                data = json.loads(result_path.read_text()) if result_path.exists() else {'gates': {}, 'serial_markers': []}
                markers = data.get('serial_markers', [])
                for target, r in repro:
                    seen_fail = any(r['failure'] in m for m in markers)
                    seen_ok = any(r['success'] in m for m in markers)
                    results.append({'name': 'reported problem: %s %s' % (target, label), 'mode': mode,
                                    'result': 'reproduced' if label == 'before' and seen_fail else
                                              'pass' if label == 'after' and seen_ok and not seen_fail else 'fail',
                                    'detail': '; '.join(m for m in markers if 'MERLINTEST' in m)[:300], 'role': 'problem-' + label})
                if label == 'after':
                    gates = data.get('gates', {})
                    for gate, ok in sorted(gates.items()):
                        results.append({'name': gate.replace('_', ' '), 'mode': mode, 'result': 'pass' if ok else 'fail',
                                        'detail': '', 'role': 'regression'})
                    if code and not gates:
                        results.append({'name': 'candidate test run', 'mode': mode, 'result': 'fail', 'detail': 'exit %d' % code,
                                        'role': 'regression'})
        self.log('test', results=results)
        return results

    # ---- main ----
    def execute(self):
        started = time.time()
        public = {'investigator': {}, 'problems': self.record['public'].get('problems', []), 'changes': [], 'source_files': [],
                  'rebuilt': [], 'tests': [], 'fixed': [], 'limitations': [], 'risks': [], 'candidate': {}, 'ready_to_apply': False}
        try:
            ws = self.workspace()
            analysis = self.investigate(ws)
            files, targets = self.changed_targets(ws, analysis)
            public['investigator'] = analysis['investigator']
            public['analysis'] = analysis['summary']
            public['changes'] = [{'file': e['file'], 'summary': e['why']} for e in analysis['edits']]
            public['source_files'] = files
            by_id = {r['id']: r for r in analysis['problems']}
            for p in public['problems']:
                r = by_id.get(p['id'], {})
                p['classification'] = r.get('classification', 'unknown')
                p['conclusion'] = r.get('conclusion', '')
                p['result'] = r.get('result_hint', 'unresolved') if r.get('result_hint') != 'fix_proposed' else 'pending'
            if analysis['investigator'].get('kind') == 'offline':
                public['limitations'].append('No AI model was configured on this builder: the offline rule-based investigator '
                                             'decided. It repairs only unchecked NULL pointers and classifies common non-XP25 causes.')
            unbuildable = [f for f in files if not any(f.startswith(i['source'].rstrip('/') + '/') for i in targets.values())]
            if unbuildable:
                public['limitations'].append('Changed files outside the automatically rebuilt components were not built: ' + ', '.join(unbuildable))
            if not targets:
                self.store.update(self.job, public=dict(public, status='no_change', stage='no source change is justified',
                                                        not_ready_reason='no XP25 source change was made',
                                                        data_migration='Nothing to apply.', rollback='Nothing to roll back.'))
                self.log('finished', status='no_change', seconds=int(time.time() - started))
                return
            self.stage('building', 'checking the change with a cross-compiler')
            check = self.compile_check(ws)
            if check.get('status') != 'compiled_static_checks_passed':
                raise StepFailed('the changed source does not compile: ' + str(check.get('error', ''))[-500:])
            collect = self.native(ws)
            public['rebuilt'] = sorted(i['target'] for i in targets.values())
            candidate = self.assemble(collect, targets)
            public['candidate'] = {k: candidate[k] for k in ('sha256', 'delta_sha256', 'revision', 'base')}
            public['candidate']['files'] = [{'path': f['guest_path'], 'sha256': f['sha256']} for f in candidate['files']]
            public['candidate_available'] = True
            self.store.update(self.job, public=public)
            tests = self.test(candidate, targets, analysis)
            public['tests'] = [{k: t[k] for k in ('name', 'mode', 'result', 'detail')} for t in tests]
            regression_ok = all(t['result'] == 'pass' for t in tests if t['role'] == 'regression') and \
                any(t['role'] == 'regression' for t in tests)
            after_ok = all(t['result'] == 'pass' for t in tests if t['role'] == 'problem-after')
            reproduced = any(t['result'] == 'reproduced' for t in tests if t['role'] == 'problem-before')
            for p in public['problems']:
                r = by_id.get(p['id'], {})
                if r.get('change_justified'):
                    if after_ok and reproduced and any(t['role'] == 'problem-after' for t in tests):
                        p['result'] = 'fixed_verified'
                    elif after_ok and not reproduced:
                        p['result'] = 'not_reproducible'
                    else:
                        p['result'] = 'unresolved'
            public['fixed'] = [p['title'] for p in public['problems'] if p['result'] == 'fixed_verified']
            public['risks'] = ['Only the rebuilt files change; the candidate was tested on the builder\'s baseline image, not on this '
                               'computer\'s own disk. The deployment agent checks each file\'s installed hash before replacing it and '
                               'refuses if this computer differs.']
            public['data_migration'] = ('Your system disk is kept. The update is applied to a new image layered on it (QCOW2 '
                                        'overlay), changing only the listed files; documents, settings and installed programs stay.')
            public['rollback'] = ('The previous system image stays unchanged on the host. Roll Back switches back to it; changes '
                                  'made after the update stay in the newer image but are not visible after rolling back.')
            ready = bool(public['fixed']) and regression_ok
            public['ready_to_apply'] = ready
            if not ready:
                public['not_ready_reason'] = 'regression tests failed' if not regression_ok else 'no reported problem was verified as fixed'
            self.store.update(self.job, public=dict(public, status='ready' if ready else 'failed',
                                                    stage='tested candidate ready to apply' if ready else public['not_ready_reason']))
            self.log('finished', status='ready' if ready else 'failed', seconds=int(time.time() - started))
        except Cancelled:
            self.cleanup()
            self.store.update(self.job, public=dict(public, status='cancelled', stage='cancelled by the user; evidence kept'))
            self.log('finished', status='cancelled')
        except (StepFailed, subprocess.CalledProcessError, OSError, ValueError, KeyError, RuntimeError) as e:
            self.cleanup()
            self.store.update(self.job, public=dict(public, status='failed', stage=str(e)[:300], ready_to_apply=False,
                                                    not_ready_reason=str(e)[:300]))
            self.log('finished', status='failed', error=str(e)[:2000], type=type(e).__name__)

    def cleanup(self):
        for p in list(self.processes):
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
