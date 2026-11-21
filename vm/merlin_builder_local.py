#!/usr/bin/env python3
"""Run the MerlinAI Builder pipeline on this host for development (not the
deployment form: that is the builder VM, components/merlin/builder/deploy).

  merlin_builder_local.py init --dir .work/<fresh> --commit COMMIT --baseline-image IMG --baseline-sha256 H
                               --revision NAME --symbols DIR [--modes up,mp,tcg]
      a builder data directory, a source-only baseline repository of COMMIT
      (Source/ excluded, as on the builder VM) and config.json; registers the
      installation "dev-merlin" and prints its key
  merlin_builder_local.py submit --dir DIR --problem-json FILE [--explanation TEXT]
      submits a build request as the installation would (XP25-MERLIN1)
  merlin_builder_local.py run --dir DIR
      runs every queued job once (merlin_builder run --once)"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
sys.path.insert(0, str(ROOT / 'components/merlin/builder/deploy'))


def init(args):
    from merlin_builder.store import Store
    from merlin_builder.server import DEFAULT_LIMITS
    import builder_vm
    d = args.dir.resolve()
    if not d.is_relative_to(ROOT / '.work'):
        raise SystemExit('a fresh .work/ directory is required')
    d.mkdir(parents=True, exist_ok=False)
    bundle = d / 'baseline.bundle'
    snap = builder_vm.snapshot_bundle(ROOT, args.commit, bundle)
    subprocess.run(['git', 'clone', '--quiet', '--bare', str(bundle), str(d / 'baseline.git')], check=True)
    subprocess.run(['chmod', '-R', 'a-w', str(d / 'baseline.git')], check=True)
    reference = ROOT / '.work/merlin-builder-vm-20261121/reference'
    config = {
        'listen': '127.0.0.1:0', 'data': str(d / 'data'), 'log': str(d / 'api.jsonl'), 'tools': str(ROOT),
        'toolchain': str(ROOT / '.work/toolchains/mingw-binutils/usr/bin'), 'default_baseline': 'xp25-m9',
        'baselines': {'xp25-m9': {
            'repository': str(d / 'baseline.git'), 'commit': snap, 'image': str(args.baseline_image.resolve()),
            'image_format': 'qcow2', 'image_sha256': args.baseline_sha256, 'revision': args.revision,
            'build_vm': str(ROOT / '.work/merlin-20261121/reference/build-vm-ai/disk.qcow2'),
            'guest_modules': str(reference / 'guest-modules/WINDOWS/system32'), 'symbols': str(args.symbols.resolve()),
            'mp_kernel': str(reference / 'kernel/ntkrnlmp.exe'), 'mp_hal': str(reference / 'kernel/halmacpi.dll')}},
        'provider': {'kind': 'offline'}, 'test_modes': args.modes.split(','), 'sandbox_network': True,
        'limits': {'job_disk_reserve_gb': 10}}
    (d / 'config.json').write_text(json.dumps(config, indent=1) + '\n')
    key = Store(config['data'], dict(DEFAULT_LIMITS)).register_installation('dev-merlin', 'xp25-m9')
    (d / 'installation.key').write_text(key + '\n')
    (d / 'installation.key').chmod(0o600)
    print(json.dumps({'dir': str(d), 'baseline_snapshot_commit': snap, 'source_commit': args.commit}))


def submit(args):
    from merlin_builder import protocol
    from merlin_builder.server import DEFAULT_LIMITS, Server
    from merlin_builder.store import Store
    d = args.dir.resolve()
    config = json.loads((d / 'config.json').read_text())
    store = Store(config['data'], dict(DEFAULT_LIMITS))
    server = Server(('127.0.0.1', 0), store, dict(DEFAULT_LIMITS), log_path=config['log'])
    threading.Thread(target=server.serve_forever, daemon=True).start()
    key = bytes.fromhex((d / 'installation.key').read_text().strip())
    problem = json.loads(args.problem_json.read_text())
    problem = problem.get('problem', problem)
    body = json.dumps({'schema': 'xp25-merlin-build/1', 'problems': [problem],
                       'request': {'explanation': args.explanation, 'requested_by': 'developer', 'requested_at': ''}}).encode()
    client = protocol.Client('http://127.0.0.1:%d' % server.server_address[1], 'dev-merlin', key)
    status, data = client.call('POST', '/jobs', body)
    server.shutdown()
    print(status, data.decode())


def run(args):
    d = args.dir.resolve()
    return subprocess.call([sys.executable, '-m', 'merlin_builder', 'run', '--once', '--config', str(d / 'config.json')],
                           cwd=ROOT / 'components/merlin/builder')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('init')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--baseline-image', type=Path, required=True)
    p.add_argument('--baseline-sha256', required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--symbols', type=Path, required=True)
    p.add_argument('--modes', default='up')
    p = sub.add_parser('submit')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('--problem-json', type=Path, required=True)
    p.add_argument('--explanation', default='')
    p = sub.add_parser('run')
    p.add_argument('--dir', type=Path, required=True)
    args = parser.parse_args()
    return {'init': init, 'submit': submit, 'run': run}[args.action](args) or 0


if __name__ == '__main__':
    sys.exit(main())
