"""Command line for the MerlinAI Builder.

  python3 -m merlin_builder serve --config CONFIG          the API (control plane)
  python3 -m merlin_builder run --config CONFIG            the job runner (execution plane)
  python3 -m merlin_builder register-installation --config CONFIG ID [--baseline NAME]
  python3 -m merlin_builder register-agent --config CONFIG NAME INSTALLATION...
  python3 -m merlin_builder jobs --config CONFIG           list every job (administrator view)
Keys are printed once, to standard output, for the administrator to hand to
the installation (MerlinAI Settings) or to the deployment agent."""
import argparse
import json
from pathlib import Path
import sys


def load(path):
    config = json.loads(Path(path).read_text())
    config.setdefault('limits', {})
    return config


def main(argv=None):
    parser = argparse.ArgumentParser(prog='merlin_builder', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['serve', 'run', 'register-installation', 'register-agent', 'jobs'])
    parser.add_argument('names', nargs='*')
    parser.add_argument('--config', required=True)
    parser.add_argument('--baseline', default=None)
    parser.add_argument('--once', action='store_true', help='run: process queued jobs, then exit')
    args = parser.parse_intermixed_args(argv)
    config = load(args.config)
    from .server import DEFAULT_LIMITS
    limits = dict(DEFAULT_LIMITS, **config['limits'])
    if args.command == 'serve':
        from .server import serve
        return serve(config)
    if args.command == 'run':
        from .runner import run
        return run(config, once=args.once)
    from .store import Store
    store = Store(config['data'], limits)
    if args.command == 'register-installation':
        if len(args.names) != 1:
            parser.error('one installation id')
        baseline = args.baseline or config.get('default_baseline')
        if baseline not in config.get('baselines', {}):
            parser.error('unknown baseline; configured: ' + ', '.join(config.get('baselines', {})))
        key = store.register_installation(args.names[0], baseline)
        print(json.dumps({'installation': args.names[0], 'builder_key': key, 'baseline': baseline}))
        return 0
    if args.command == 'register-agent':
        if len(args.names) < 2:
            parser.error('agent name and at least one installation')
        key = store.register_agent(args.names[0], args.names[1:])
        print(json.dumps({'agent': args.names[0], 'key': key, 'installations': args.names[1:]}))
        return 0
    if args.command == 'jobs':
        for job, record in store.all_jobs():
            p = record['public']
            print(job, record['installation'], p['status'], p.get('stage', ''))
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
