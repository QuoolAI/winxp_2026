#!/usr/bin/env python3
"""Collect a finished native XP25 AI build from a frozen build-VM disk:
extract the five binaries, PDBs and logs read-only, confirm the extracted
sources match the media manifest, verify every import against the guest's
own system DLL exports, and assemble a test directory with the MinGW-built
guest probe (probes are cross-compiled, as for every other XP25 probe)."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
from ai_build import verify

OUTPUTS = {'xp25agent.dll': 'xp25-agent/dll', 'XP25Broker.exe': 'xp25-agent/broker', 'ClippyAI.exe': 'clippyai/app',
           'RoverAI.exe': 'roverai/app', 'RoverAIBand.dll': 'roverai/explorer'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disk', type=Path, required=True)
    parser.add_argument('--out-name', required=True, help='C:\\xpout\\<name> used by the build')
    parser.add_argument('--media', type=Path, required=True, help='prepare_ai.py output directory')
    parser.add_argument('--probe', type=Path, required=True, help='MinGW-built ai_probe.exe')
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    guest = []
    for name, folder in OUTPUTS.items():
        stem = name.rsplit('.', 1)[0]
        guest += ['/nt/xp25/ai/%s/obj/i386/%s' % (folder, name), '/nt/xp25/ai/%s/obj/i386/%s.pdb' % (folder, stem)]
    manifest = json.loads((args.media / 'manifest.json').read_text())
    sources = [f for f in manifest['files'] if f.startswith('ai/') and f.endswith(('.c', '.h', 'sources'))]
    guest += ['/nt/xp25/' + f for f in sources]
    guest += ['/xpout/%s/%s' % (args.out_name, f) for f in ('native.log', 'build.log', 'build.err', 'build.wrn')]
    extracted = out / 'extracted'
    subprocess.run([sys.executable, str(ROOT / 'vm/read_guest.py'), str(args.disk), str(extracted)] + guest)
    records = {r['guest_path']: r for r in json.loads((extracted / 'files.json').read_text())['files']}
    mismatched = [f for f in sources if records.get('/nt/xp25/' + f, {}).get('sha256') != manifest['files'][f]]
    build = out / 'build'
    build.mkdir(parents=True, exist_ok=False)
    result = {'disk': str(args.disk), 'media_iso_sha256': manifest['iso_sha256'], 'sources_checked': len(sources),
              'sources_mismatched': mismatched, 'binaries': {}}
    objdump = str(args.toolchain / 'i686-w64-mingw32-objdump')
    local = {'xp25agent.dll': set(l.strip() for l in (ROOT / 'components/xp25-agent/dll/xp25agent.def').read_text().splitlines()[3:] if l.strip())}
    for name, folder in OUTPUTS.items():
        src = extracted / ('nt/xp25/ai/%s/obj/i386/%s' % (folder, name))
        shutil.copy2(src, build / name)
        result['binaries'][name] = {'sha256': hashlib.sha256(src.read_bytes()).hexdigest(), 'bytes': src.stat().st_size,
                                    'imports': verify(objdump, build / name, local, exact_51=False)}
    shutil.copy2(args.probe, build / 'ai_probe.exe')
    result['probe'] = {'source': str(args.probe), 'sha256': hashlib.sha256(args.probe.read_bytes()).hexdigest()}
    result['status'] = 'native_binaries_collected' if not mismatched else 'source_mismatch'
    (out / 'collect.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'binaries'}, indent=2))
    for name, b in result['binaries'].items():
        print(name, b['sha256'], b['bytes'])
    return 0 if not mismatched else 2


if __name__ == '__main__':
    raise SystemExit(main())
