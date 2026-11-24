#!/usr/bin/env python3
"""Prepare native build media that adds kernel exports to ntoskrnl.src.

KeFlushQueuedDpcs is implemented in the NT 5.1.2600.1106 kernel source
(base/ntos/ke/dpcobj.c) and declared in ntddk.h, but that tree does not export
it; the Service Pack 2 and later kernels do. The installed Service Pack 3
ipnat.sys (the Windows Firewall driver) imports it, so the firewall cannot
load on the source-built kernel. Only the export list changes: the routine is
Microsoft's own, already linked into the kernel. Source/ is not modified; the
patched list is generated under .work/ and applied to the build VM's
disposable C:\\nt copy."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
from merlin_builder import recipes  # noqa: E402
SOURCE = ROOT / 'Source/XPSP1/NT/base/ntos/init/ntoskrnl.src'
# export -> existing line it is inserted after; every routine must already be compiled into the kernel.
EXPORTS = {'KeFlushQueuedDpcs': '    KeInsertQueueDpc\n'}
IMPLEMENTATIONS = {'KeFlushQueuedDpcs': 'base/ntos/ke/dpcobj.c'}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    original = SOURCE.read_bytes()
    for name in EXPORTS:
        implementation = (ROOT / 'Source/XPSP1/NT' / IMPLEMENTATIONS[name]).read_text('latin1')
        if '\n' + name + '(' not in implementation.replace(' (', '('):
            parser.error(name + ' is not implemented in ' + IMPLEMENTATIONS[name])
    # The same insertion gives the MerlinAI Builder its effective kernel source (merlin_builder/recipes.py).
    try:
        text = recipes.apply_exports(original.decode('latin1'), EXPORTS)
    except ValueError as error:
        parser.error(str(error))
    out.mkdir(parents=True, exist_ok=False)
    media = out / 'media'
    (media / 'original').mkdir(parents=True)
    (media / 'patched').mkdir()
    patched = text.encode('latin1')
    (media / 'original/ntoskrnl.src').write_bytes(original)
    (media / 'patched/ntoskrnl.src').write_bytes(patched)
    (media / 'build.cmd').write_bytes((ROOT / 'build/native-kernel-export-build.cmd').read_bytes()
                                      .replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    iso = out / 'native-kernel-exports.iso'
    command = ['xorriso', '-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-R', '-V', 'XP25KX', '-o', str(iso), str(media)]
    subprocess.run(command, check=True)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    (out / 'manifest.json').write_text(json.dumps({
        'command': command, 'iso_sha256': digest(iso.read_bytes()), 'added_exports': sorted(EXPORTS),
        'implementations': IMPLEMENTATIONS, 'original_sha256': digest(original), 'patched_sha256': digest(patched),
        'changed_lines': len(EXPORTS), 'scope': 'ntoskrnl.src export list only; no kernel source file changes; Source/ unchanged.'},
        indent=2) + '\n')
    print(iso)


if __name__ == '__main__':
    main()
