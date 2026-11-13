#!/usr/bin/env python3
"""Collect a finished Milestone 8.2 native build from its frozen build-VM disk.

Read-only (vm/read_guest.py): the outputs listed on the media, every per-directory
build log, and the copies of the listed source files that the build VM compiled.
The build is accepted only when
  - every compiled source file is the patched copy (or, for a control build, the
    audited original) recorded in the media manifest;
  - every directory's build.log names each listed source file of that directory as
    compiled, and no log reports an error or a failed nmake;
  - every listed output exists.

usage: cve_collect_native.py --disk FROZEN_DISK --out-name NAME --media MEDIA_DIR --output .work/<fresh>"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def guest(path):
    return '/' + path.replace('\\', '/')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--disk', type=Path, required=True)
    parser.add_argument('--out-name', required=True, help='C:\\xpout\\<name> used by the build')
    parser.add_argument('--media', type=Path, required=True, help='prepare_cve.py output directory')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.media / 'manifest.json').read_text())
    out = args.output.resolve()
    sources = sorted(manifest['files'])
    logs, optional = [], []
    for step in range(1, len(manifest['dirs']) + 1):
        logs += ['/xpout/%s/build-%d.log' % (args.out_name, step), '/xpout/%s/step%d-build.log' % (args.out_name, step)]
        # build.err and build.wrn exist only when a step reported errors or warnings
        optional += ['/xpout/%s/step%d-build.%s' % (args.out_name, step, ext) for ext in ('err', 'wrn')]
    required = [guest('nt/' + o) for o in manifest['outputs']] + [guest('nt/' + s) for s in sources] + logs
    extracted = out / 'extracted'
    subprocess.run([sys.executable, str(ROOT / 'vm/read_guest.py'), str(args.disk), str(extracted)] + required + optional)
    records = {r['guest_path']: r for r in json.loads((extracted / 'files.json').read_text())['files']}
    result = {'disk': str(args.disk), 'media_iso_sha256': manifest['iso_sha256'], 'control': manifest['control'],
              'patches': manifest['patches'], 'sources': {}, 'logs': {}, 'outputs': {}, 'problems': []}
    result['problems'] += ['could not read ' + name for name in required if 'sha256' not in records.get(name, {})]
    for path in sources:
        expected = manifest['files'][path]['original_sha256' if manifest['control'] else 'patched_sha256']
        found = records.get(guest('nt/' + path), {}).get('sha256')
        result['sources'][path] = {'expected': expected, 'compiled_copy': found}
        if found != expected:
            result['problems'].append('compiled copy of %s is not the expected file' % path)
    for step, directory in enumerate(manifest['dirs'], 1):
        text = ''
        for name in ('build-%d.log' % step, 'step%d-build.log' % step):
            file = extracted / ('xpout/%s/%s' % (args.out_name, name))
            if file.is_file():
                text += file.read_text('latin-1')
        err = extracted / ('xpout/%s/step%d-build.err' % (args.out_name, step))
        compiled = sorted(set(m.lower() for m in re.findall(r'Compiling - ([\w.\\-]+)', text)))
        mine = [s for s in sources if s.replace('/', '\\').lower().startswith(directory.lower() + '\\')]
        missing = [s for s in mine if Path(s).name.lower() not in [Path(c.replace('\\', '/')).name for c in compiled]]
        errors = [line.strip() for line in text.splitlines()
                  if re.search(r'\berror\b|nmake\.exe failed|fatal', line, re.I) and 'warning' not in line.lower()]
        result['logs'][directory] = {'compiled': len(compiled), 'listed_sources_compiled': not missing,
                                     'linked': 'Linking' in text, 'error_lines': errors[:20],
                                     'err_file_bytes': err.stat().st_size if err.is_file() else 0}
        if missing:
            result['problems'].append('%s: build.log does not show %s compiled' % (directory, ', '.join(missing)))
        if errors or (err.is_file() and err.stat().st_size):
            result['problems'].append('%s: errors reported' % directory)
    binaries = out / 'binaries'
    binaries.mkdir()
    for output in manifest['outputs']:
        file = extracted / ('nt/' + output.replace('\\', '/'))
        if not file.is_file():
            result['problems'].append('missing output ' + output)
            continue
        shutil.copy2(file, binaries / file.name)
        data = file.read_bytes()
        result['outputs'][output] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    result['status'] = 'accepted' if not result['problems'] else 'not_accepted'
    (out / 'collect.json').write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('sources',)}, indent=1))
    return 0 if result['status'] == 'accepted' else 2


if __name__ == '__main__':
    raise SystemExit(main())
