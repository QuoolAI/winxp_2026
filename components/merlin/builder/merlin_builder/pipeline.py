"""MerlinAI build pipeline for one job (the execution plane).

  workspace    a fresh clone of the immutable baseline repository at the
               approved commit, for this job alone
  investigate  model or offline investigator (merlin_builder.investigate)
  checks       MinGW cross-compile of changed MerlinAI sources, no network
  native       per recipe (components.json), the NT 5.1 toolchain build in a
               disposable clone of the build VM; a Microsoft-source recipe
               also builds XP25's unchanged sources (control build)
  provenance   a control build must reproduce the installed binary, and the
               candidate may differ from it only by the job's change
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

from . import investigate as inv, pe, recipes, sysimage
from .store import now

PIPELINE_VERSION = 1


class Cancelled(Exception):
    pass


def kill_job_guests(job):
    """Stop the QEMU guests of a job (build VM merlin-<job>, test VMs merlin-<job>-...). The tools start QEMU in its own
    session, so killing a step's process group leaves them running; they are found by their -name, which carries the job."""
    marker = job.lower()
    killed = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            argv = (proc / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if not argv or not os.path.basename(argv[0].decode(errors='replace')).startswith('qemu-system'):
            continue
        names = [argv[i + 1].decode(errors='replace') for i, a in enumerate(argv[:-1]) if a == b'-name']
        if any(marker in n for n in names):
            try:
                os.kill(int(proc.name), signal.SIGKILL)
                killed.append(int(proc.name))
            except OSError:
                pass
    return killed


class StepFailed(Exception):
    pass


def groups_target(groups, name):
    for binaries in groups.values():
        if name in binaries:
            return binaries[name]['target']
    return name


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
                    kill_job_guests(self.job)
                    raise StepFailed('%s timed out after %d s' % (step, timeout))
                if self.store.load(self.job).get('cancel_requested'):
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
                    kill_job_guests(self.job)
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

    def system_image(self):
        sys.path.insert(0, str(self.tools / 'vm'))
        import xp_lab as lab
        return sysimage.SystemImage(self.baseline['image'], self.dir / 'system-image', lab)

    def investigate(self, ws):
        self.stage('investigating', 'investigating the reported problems')
        workspace = inv.Workspace(ws, reference=self.config.get('reference_source'), overlay=self.dir / 'nt-overlay')
        system = self.system_image()
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
                                                 log=tool_log, max_steps=int(provider_config.get('max_steps', 30)), system=system)
        else:
            investigator = inv.OfflineInvestigator(workspace, symbols, log=tool_log, system=system)
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
        """The edited files and {recipe: {binary: info}}: for each recipe whose sources an edit touched, its
        installed binaries built from that source (all of the recipe's binaries for a shared file and for an
        NT recipe, which relinks as a whole)."""
        table = recipes.load()
        files = sorted({e['file'] for e in analysis['edits']})
        groups = {}
        for f in files:
            recipe = recipes.recipe_of_file(f, table)
            if not recipe:
                continue
            members = {n: i for n, i in recipes.binaries_of(recipe, table).items() if i.get('guest_path')}
            own = {n: i for n, i in members.items() if f.startswith(i['source'].rstrip('/') + '/')}
            groups.setdefault(recipe, {}).update(own if own and table['recipes'][recipe]['kind'] == 'xp25' else members)
        return files, groups

    def compile_check(self, ws, quiet=False):
        out = ws / '.work' / ('mingw-check-%d' % int(time.time() * 1000))     # the workspace's own .work, as its tools require
        code = self.run([sys.executable, ws / 'build/merlin_build.py', '--toolchain', self.config['toolchain'], '--output', out,
                         '--guest-modules', self.baseline['guest_modules']], 'compile-check', 900, cwd=ws)
        result = json.loads((out / 'result.json').read_text()) if (out / 'result.json').exists() else {'status': 'no result'}
        if quiet:
            return json.dumps({'status': result.get('status'), 'error': result.get('error', '')[-1500:]})
        return result

    def control_source(self):
        """A second checkout of the baseline commit, never edited: the source of control builds."""
        control = self.dir / 'control-workspace'
        if not control.exists():
            repo, commit = self.baseline['repository'], self.baseline['commit']
            for argv in (['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', repo, str(control)],
                         ['git', '-C', str(control), 'checkout', '--quiet', '-b', 'control-' + self.job, commit]):
                r = subprocess.run(argv, capture_output=True, text=True)
                if r.returncode:
                    raise StepFailed('the control source could not be checked out: ' + r.stderr[-300:])
        return control

    def native(self, ws, groups):
        """Build every changed recipe natively: {recipe: {'candidate': collection, 'control': collection}}. An NT
        recipe builds control and candidate in one build VM (both in one collection); an XP25 recipe with a
        control build builds the unchanged baseline source separately first."""
        table = recipes.load()
        collections = {}
        for recipe in sorted(groups):
            kind = table['recipes'][recipe]['kind']
            stages = [('control', self.control_source()), ('candidate', ws)] \
                if kind == 'xp25' and table['recipes'][recipe].get('control_build') else [('candidate', ws)]
            collections[recipe] = {}
            for stage, source in stages:
                what = ', '.join(sorted(i['target'] for i in groups[recipe].values()))
                self.stage('building', 'building %s with the NT 5.1 toolchain%s' % (what, ' (unchanged source, control build)'
                                                                                     if stage == 'control' else ''))
                # The native build driver accepts media only under the tools' own .work (as for every lab tool).
                media = self.tools / '.work' / 'merlin-jobs' / self.job / ('media-%s-%s' % (recipe, stage))
                media.parent.mkdir(parents=True, exist_ok=True)
                argv = [sys.executable, self.tools / 'build/prepare_recipe.py', '--recipe', recipe, '--output', media, '--source', source]
                if kind == 'nt':
                    argv += ['--reference', self.config['reference_source'], '--nt-changes', self.dir / 'nt-overlay']
                if self.run(argv, 'native-media-%s-%s' % (recipe, stage), 600, sandbox=False):
                    raise StepFailed('native build media for %s could not be prepared' % recipe)
                name = 'merlin-%s-%s-%s' % (self.job.lower(), recipe, stage)
                code = self.run([sys.executable, self.tools / 'vm/native_recipe_build.py', '--media', media, '--name', name,
                                 '--base', self.baseline['build_vm'], '--guest-modules', self.baseline['guest_modules'],
                                 '--toolchain', self.config['toolchain']], 'native-build-%s-%s' % (recipe, stage),
                                int(self.config.get('native_timeout', 3600)), sandbox=False)
                collect = self.tools / '.work/boot-debug-20261022' / name / 'collect'
                record = json.loads((collect / 'collect.json').read_text()) if (collect / 'collect.json').exists() else None
                if code or not record or record.get('status') != 'accepted':
                    raise StepFailed('the native build of %s failed: %s' % (recipe, (record or {}).get('problems') or 'no collection'))
                self.log('native', recipe=recipe, stage=stage, collection=str(collect),
                         binaries={k: v['sha256'] for k, v in record['binaries'].items()})
                collections[recipe][stage] = collect
            if kind == 'nt':
                collections[recipe]['control'] = collections[recipe]['candidate']
        return collections

    @staticmethod
    def built(collections, recipe, stage, info, variant=None):
        """A built file: build/<target> of an XP25 recipe's stage, build/<stage>/<file> of an NT recipe."""
        if variant:
            return collections[recipe][stage] / 'build' / stage / Path(info['variants'][variant]).name
        return collections[recipe][stage] / 'build' / info['target']

    def provenance(self, collections, groups):
        """Check each rebuilt binary against what is installed. Where there is a control build (NT recipes, XP25
        recipes with control_build), it must reproduce the installed binary exactly (link time stamps and debug
        records aside): otherwise the job's source is not what the installed binary was built from, and replacing
        it would change more than the fix. Every import of a rebuilt binary must resolve on the installed system
        (or against another rebuilt binary). Returns {binary: (new file, record)} and the kernels the tests boot
        ({'mp': candidate multiprocessor kernel} when the kernel was rebuilt)."""
        table = recipes.load()
        system = self.system_image()
        out, test_kernels = {}, {}
        with system.open():
            for recipe, binaries in sorted(groups.items()):
                kind = table['recipes'][recipe]['kind']
                for name, info in sorted(binaries.items()):
                    try:
                        installed = system.read(info['guest_path'])
                    except RuntimeError:
                        raise StepFailed('%s is not installed in the baseline image; the builder replaces files, it never adds them'
                                         % info['guest_path'])
                    installed_sha = hashlib.sha256(installed).hexdigest()
                    known = info.get('known_builds')
                    if known is not None and installed_sha not in known:
                        raise StepFailed('the installed %s (%s) is not a build whose source is known; rebuilding it would change '
                                         'more than the fix' % (info['target'], installed_sha[:16]))
                    record = {'installed_sha256': installed_sha}
                    if known:
                        record['known_build'] = known[installed_sha]
                    variant = known[installed_sha]['variant'] if kind == 'nt' else None
                    candidate_path = self.built(collections, recipe, 'candidate', info, variant)
                    candidate = candidate_path.read_bytes()
                    if 'control' in collections[recipe]:
                        control = self.built(collections, recipe, 'control', info, variant).read_bytes()
                        reproduced = pe.compare_builds(installed, control)
                        if not reproduced['identical']:
                            raise StepFailed('the unchanged source of this baseline does not reproduce the installed %s (%s): it was '
                                             'built from other source, so a rebuild would change more than the fix' %
                                             (info['target'], '; '.join(reproduced['differences'])[:300]))
                        before, after = set(pe.PE(control).exports()), set(pe.PE(candidate).exports())
                        change = pe.compare_builds(control, candidate, ignore_exports=kind == 'nt')
                        record.update(control_reproduces_installed=True, exports_added=sorted(after - before),
                                      exports_removed=sorted(before - after), code_identical_to_control=change['identical'],
                                      code_differences=change['differences'])
                        if before - after:
                            raise StepFailed('the candidate %s drops exports: %s' % (info['target'], ', '.join(sorted(before - after))))
                    else:
                        record['provenance'] = table['recipes'][recipe].get('provenance', 'not established by a control build')
                    if variant:
                        record['variant'] = variant
                    out[name] = (candidate_path, record)
                    if kind == 'nt' and variant != 'mp' and 'mp' in info['variants']:
                        # The two-CPU test boots the candidate's multiprocessor build: its control build must reproduce
                        # the multiprocessor kernel the baseline's tests boot.
                        mp_control = self.built(collections, recipe, 'control', info, 'mp').read_bytes()
                        same = pe.compare_builds(Path(self.baseline['mp_kernel']).read_bytes(), mp_control)
                        if not same['identical']:
                            raise StepFailed('the control build does not reproduce the multiprocessor kernel of the two-CPU tests (%s)'
                                             % '; '.join(same['differences'])[:300])
                        test_kernels['mp'] = self.built(collections, recipe, 'candidate', info, 'mp')
                        record['mp_control_reproduces_test_kernel'] = True
            # Imports: against the other rebuilt binaries first, else the installed system.
            fresh = {Path(info_path).name.lower(): pe.PE(Path(info_path).read_bytes()) for info_path, _ in out.values()}
            for name, (path, record) in out.items():
                missing = []
                for dll, names in sorted(pe.PE(path.read_bytes()).imports().items()):
                    exporter = fresh.get(dll)
                    if exporter is None:
                        source = system.exporter(dll)
                        if not source:
                            missing.append(dll + ' (not installed)')
                            continue
                        exporter = pe.PE(system.read(source))
                    available = set(exporter.exports()) | exporter.export_ordinals()
                    missing += ['%s!%s' % (dll, n) for n in names if n not in available]
                if missing:
                    raise StepFailed('the rebuilt %s imports what the installed system does not provide: %s' %
                                     (groups_target(groups, name), ', '.join(missing)[:300]))
                record['imports_resolve_on_installed_system'] = True
        self.log('provenance', binaries={n: r for n, (_, r) in out.items()}, test_kernels={k: str(v) for k, v in test_kernels.items()})
        return out, test_kernels

    def assemble(self, rebuilt, targets):
        """rebuilt: {binary: (new file, provenance record)}; targets: {binary: registry entry}."""
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
        files, sources = [], []
        cwd = os.getcwd()
        os.chdir(image_dir)
        try:
            with lab.partition(candidate, True) as device:
                for name, info in sorted(targets.items()):
                    new = rebuilt[name][0]
                    before = lab.run(['ntfscat', device, info['guest_path']])
                    lab.run(['ntfscp', device, str(new), info['guest_path']])
                    after = lab.run(['ntfscat', device, info['guest_path']])
                    if hashlib.sha256(after).hexdigest() != sha(new):
                        raise StepFailed('offline replacement of %s did not take effect' % info['guest_path'])
                    files.append({'guest_path': info['guest_path'], 'sha256': sha(new), 'bytes': new.stat().st_size,
                                  'expected_before': hashlib.sha256(before).hexdigest(), 'component': info['target']})
                    sources.append(new)
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
                sources.append(revision_file)
        finally:
            os.chdir(cwd)
        for i, source in enumerate(sources):
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

    def problem_checks(self, analysis, targets):
        """{problem id: [check]} for the problems a change was made for. A check is a reproduce command of a
        rebuilt binary the report names (its component map entry), or, for a driver that did not load, whether
        that installed driver service runs. Report text never becomes a command: driver names are validated
        and must be installed drivers."""
        by_id = {r['id']: r for r in analysis['problems']}
        repro = [(info['target'], info['reproduce']) for info in targets.values() if info.get('reproduce')]
        system = self.system_image()
        out = {}
        with system.open():
            for p in self.request['problems']:
                if not by_id.get(p['id'], {}).get('change_justified'):
                    continue
                named = {(p.get('app') or '').lower(), (p.get('module') or '').lower()}
                checks = [{'run': r['command'], 'failure': r['failure'], 'success': r['success'], 'label': target}
                          for target, r in repro if target.lower() in named]
                if p.get('kind') == 'driver':
                    for name in inv.driver_names(p):
                        if system.find(name + '.sys'):
                            checks.append({'run': {'driver': name}, 'failure': 'XP25_JOBTEST_DRIVER_%s=not_running' % name.upper(),
                                           'success': 'XP25_JOBTEST_DRIVER_%s=running' % name.upper(), 'label': name + ' driver'})
                elif not checks:
                    checks = [{'run': r['command'], 'failure': r['failure'], 'success': r['success'], 'label': target}
                              for target, r in repro]
                out[p['id']] = checks
        return out

    def test(self, candidate, targets, analysis, test_kernels=None):
        self.stage('testing', 'testing the candidate image')
        results = []
        modes = self.config.get('test_modes', ['up'])
        per_problem = self.problem_checks(analysis, targets)
        checks = []
        for rows in per_problem.values():
            for c in rows:
                if c['run'] not in checks:
                    checks.append(c['run'])
        for mode in modes:
            for label, image in (('before', self.baseline['image']), ('after', candidate['image'])):
                if label == 'before' and mode != modes[0]:
                    continue                                  # the defect is shown once, on the baseline
                run = '%s-%s-%s' % (self.job.lower(), label, mode)
                # A rebuilt kernel is tested under two CPUs as its own multiprocessor build.
                mp_kernel = (test_kernels or {}).get('mp') if label == 'after' else None
                extra = ['--mp-kernel', mp_kernel or self.baseline['mp_kernel'], '--mp-hal', self.baseline['mp_hal']] if mode == 'mp' else []
                code = self.run([sys.executable, self.tools / 'vm/merlin_jobtest.py', '--name', run, '--mode', mode,
                                 '--image', image, '--checks', json.dumps(checks), '--runs', self.dir / 'tests'] + extra,
                                'test-%s-%s' % (label, mode), int(self.config.get('test_timeout', 2700)) * (3 if mode == 'tcg' else 1),
                                sandbox=False)
                result_path = self.dir / 'tests' / run / 'results.json'
                data = json.loads(result_path.read_text()) if result_path.exists() else {'gates': {}, 'serial_markers': []}
                markers = data.get('serial_markers', [])
                for pid, rows in per_problem.items():
                    for c in rows:
                        seen_fail = any(c['failure'] in m for m in markers)
                        seen_ok = any(c['success'] in m for m in markers)
                        key = c['success'].split('=')[0]
                        results.append({'name': 'reported problem: %s %s' % (c['label'], label), 'mode': mode, 'problem': pid,
                                        'result': 'reproduced' if label == 'before' and seen_fail else
                                                  'pass' if label == 'after' and seen_ok and not seen_fail else 'fail',
                                        'detail': '; '.join(m for m in markers if key in m)[:300], 'role': 'problem-' + label})
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
            files, groups = self.changed_targets(ws, analysis)
            targets = {n: i for g in groups.values() for n, i in g.items()}
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
                                             'decided. It repairs only unchecked NULL pointers in MerlinAI and kernel functions '
                                             'that drivers import but the kernel does not export, and classifies common non-XP25 causes.')
            unbuildable = [f for f in files if recipes.recipe_of_file(f) not in groups]
            if unbuildable:
                public['limitations'].append('Changed files outside the automatically rebuilt components were not built: ' + ', '.join(unbuildable))
            if not targets:
                self.store.update(self.job, public=dict(public, status='no_change', stage='no source change is justified',
                                                        not_ready_reason='no XP25 source change was made',
                                                        data_migration='Nothing to apply.', rollback='Nothing to roll back.'))
                self.log('finished', status='no_change', seconds=int(time.time() - started))
                return
            if 'merlin' in groups:
                self.stage('building', 'checking the change with a cross-compiler')
                check = self.compile_check(ws)
                if check.get('status') != 'compiled_static_checks_passed':
                    raise StepFailed('the changed source does not compile: ' + str(check.get('error', ''))[-500:])
            collections = self.native(ws, groups)
            self.stage('building', 'checking the rebuilt files against the installed ones')
            rebuilt, test_kernels = self.provenance(collections, groups)
            public['rebuilt'] = sorted(i['target'] for i in targets.values())
            public['provenance'] = {targets[n]['target']: r for n, (_, r) in rebuilt.items()}
            candidate = self.assemble(rebuilt, targets)
            public['candidate'] = {k: candidate[k] for k in ('sha256', 'delta_sha256', 'revision', 'base')}
            public['candidate']['files'] = [{'path': f['guest_path'], 'sha256': f['sha256']} for f in candidate['files']]
            public['candidate_available'] = True
            self.store.update(self.job, public=public)
            tests = self.test(candidate, targets, analysis, test_kernels)
            public['tests'] = [{k: t[k] for k in ('name', 'mode', 'result', 'detail')} for t in tests]
            regression_ok = all(t['result'] == 'pass' for t in tests if t['role'] == 'regression') and \
                any(t['role'] == 'regression' for t in tests)
            for p in public['problems']:
                r = by_id.get(p['id'], {})
                if r.get('change_justified'):
                    mine = [t for t in tests if t.get('problem') == p['id']]
                    after = [t for t in mine if t['role'] == 'problem-after']
                    after_ok = bool(after) and all(t['result'] == 'pass' for t in after)
                    reproduced = any(t['result'] == 'reproduced' for t in mine if t['role'] == 'problem-before')
                    p['result'] = 'fixed_verified' if after_ok and reproduced else 'not_reproducible' if after_ok else 'unresolved'
            public['fixed'] = [p['title'] for p in public['problems'] if p['result'] == 'fixed_verified']
            public['risks'] = ['Only the rebuilt files change; the candidate was tested on the builder\'s baseline image, not on this '
                               'computer\'s own disk. The deployment agent checks each file\'s installed hash before replacing it and '
                               'refuses if this computer differs.']
            if test_kernels:
                public['risks'].append('This update replaces the kernel. If XP25 does not start with it, the deployment agent receives no '
                                       'healthy report and starts the previous system again. The new kernel differs from the installed '
                                       'one only as listed under provenance; its control build reproduced the installed kernel exactly.')
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
