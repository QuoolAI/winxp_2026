#!/usr/bin/env python3
"""Package the OEM probe and the interactive-VM configuration scripts as an ISO."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'tests/guest/vmconfig'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True, help='build/guest.py --probe oem output')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private media required')
    result = json.loads((args.probe / 'result.json').read_text())
    if (result['status'] != 'compiled_static_checks_passed' or result['source_sha256'] != sha(ROOT / 'tests/guest/oem_probe.c') or
            result['executable_sha256'] != sha(args.probe / 'oem_probe.exe')):
        parser.error('oem probe is stale or unverified')
    output.mkdir(parents=True, exist_ok=False)
    media = output / 'media'
    media.mkdir()
    shutil.copy2(args.probe / 'oem_probe.exe', media / 'oem_probe.exe')
    for script in sorted(SCRIPTS.glob('*.cmd')):
        text = script.read_text(encoding='ascii')
        (media / script.name).write_bytes(text.replace('\r\n', '\n').replace('\n', '\r\n').encode('ascii'))
    iso = output / 'vmconfig.iso'
    command = ['xorriso', '-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-R', '-V', 'XP25VMCFG', '-o', str(iso), str(media)]
    subprocess.run(command, check=True)
    (output / 'manifest.json').write_text(json.dumps({
        'prepare_command': [sys.executable, *sys.argv], 'command': command,
        'probe_source_sha256': result['source_sha256'], 'iso_sha256': sha(iso),
        'files': {p.name: sha(p) for p in sorted(media.iterdir())},
        'sources': {str(p.relative_to(ROOT)): sha(p) for p in sorted(SCRIPTS.glob('*.cmd'))}}, indent=2) + '\n')
    print(iso)


if __name__ == '__main__':
    main()
