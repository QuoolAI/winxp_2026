#!/usr/bin/env python3
"""Record original component artifacts and completed private guest experiments.

Unintegrated outputs and remaining installed Microsoft dependencies stay explicit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from inspect_component import PE

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'Source/XPSP1/NT'
BASELINE_NATIVE = {'ntdll.dll', 'kernel32.dll', 'user32.dll', 'gdi32.dll',
                   'secur32.dll', 'ws2_32.dll', 'ws2help.dll', 'wshtcpip.dll'}
PROVIDED_SCM_LIBRARIES = (
    'public/sdk/lib/i386/rpcutil.lib', 'public/sdk/lib/i386/rpcrt4.lib',
    'public/sdk/lib/i386/rpcndr.lib', 'public/sdk/lib/i386/secur32.lib',
    'public/sdk/lib/i386/netapi32.lib', 'public/sdk/lib/i386/ntdll.lib',
    'public/sdk/lib/i386/userenv.lib', 'public/sdk/lib/i386/scesrv.lib',
    'public/sdk/lib/i386/ntdsapi.lib', 'public/internal/windows/lib/i386/user32p.lib',
    'public/internal/ds/lib/i386/crypstub.lib', 'public/internal/com/lib/i386/trkstub.lib',
    'public/internal/admin/lib/i386/ncobjapi.lib')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', nargs=3, action='append', required=True,
                        metavar=('NAME', 'SOURCE_DIRECTORY', 'BINARY'))
    parser.add_argument('--runtime', type=Path, action='append', default=[])
    parser.add_argument('--failed-runtime', type=Path, action='append', default=[])
    parser.add_argument('--source-inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(ROOT / '.work'):
        parser.error('generated manifests must remain private under .work/')
    inventory = json.loads(args.source_inventory.read_text())
    runtimes = []
    for path in args.runtime:
        path = path.resolve()
        report = json.loads((path / 'component-results.json').read_text())
        for name, expected_hash in report['evidence_sha256'].items():
            if sha(path / name) != expected_hash:
                parser.error('runtime evidence changed after validation: ' + str(path / name))
        checkpoint = json.loads((path / 'checkpoint.json').read_text())
        inputs = json.loads((path / 'inputs.json').read_text())
        target = (inputs.get('recovery') or {}).get('target')
        if not report['passed'] or checkpoint['stage'] != 'normal_shutdown_frozen':
            parser.error('runtime must have passed and shut down normally: ' + str(path))
        extensions = None
        if (path / 'extension-results.json').exists():
            extensions = json.loads((path / 'extension-results.json').read_text())
            if not extensions['passed'] or any(sha(path / name) != digest for name, digest in extensions['evidence_sha256'].items()):
                parser.error('extension evidence must be passing and fresh: ' + str(path))
        runtimes.append({'experiment': path.name, 'directory': str(path),
                         'replaced_component': target,
                         'component_sha256': inputs['staged'].get(target, {}).get('sha256'),
                         'base': inputs['base'], 'disk_sha256': checkpoint['disk_sha256'],
                         'checks': report['checks'], 'extension_checks': extensions['checks'] if extensions else None,
                         'recovery': inputs.get('recovery')})
    failures = []
    for path in args.failed_runtime:
        path = path.resolve()
        if not path.is_relative_to(ROOT / '.work') or (path / 'disk.qcow2').stat().st_mode & 0o222:
            parser.error('failed experiments must be frozen private images')
        failure = json.loads((path / 'failure.json').read_text())
        if failure.get('accepted') is not False:
            parser.error('failed runtime needs explicit rejected evidence')
        inputs = json.loads((path / 'inputs.json').read_text())
        target = (inputs.get('recovery') or {}).get('target')
        failures.append({'experiment': path.name, 'directory': str(path), 'replaced_component': target,
                         'component_sha256': inputs['staged'].get(target, {}).get('sha256'),
                         'failure': failure, 'failure_sha256': sha(path / 'failure.json')})
    components = []
    for name, source, filename in args.component:
        binary = Path(filename).resolve()
        if not binary.is_relative_to(ROOT / '.work'):
            parser.error('compiled artifacts must remain under .work/')
        directory = (REFERENCE / source).resolve()
        if not directory.is_relative_to(REFERENCE) or not (directory / 'sources').is_file():
            parser.error('an original source directory with its sources recipe is required')
        pe = PE(binary).inspect()
        if not pe['checksum_valid']:
            parser.error('invalid compiled PE checksum')
        relevant = [r for r in runtimes if r['replaced_component'] and
                    Path(r['replaced_component']).name.lower() == binary.name.lower()]
        rejected = [r for r in failures if r['component_sha256'] == pe['sha256']]
        accepted = [r for r in relevant if r['component_sha256'] == pe['sha256']]
        components.append({'name': name, 'source_path': source,
                           'source_recipe_sha256': sha(directory / 'sources'),
                           'binary': str(binary), 'sha256': pe['sha256'], 'pe': pe,
                           'runtime_status': 'verified_in_recorded_guests' if accepted else ('runtime_rejected' if rejected else 'compiled_not_integrated'),
                           'tested_artifact_variants': sorted({r['component_sha256'] for r in relevant if r['component_sha256']}),
                           'runtime_results': relevant,
                           'rejected_runtime_results': rejected,
                           'remaining_installed_microsoft_dependencies': sorted(
                               (set(pe['imports']) | set(pe['delay_imports'])) - BASELINE_NATIVE)})
    missing = [name for name in ('base/ntos/ex/exinit.c', 'base/ntos/ex/systime.c',
                                 'ds/security/gina/winlogon') if not (REFERENCE / name).exists()]
    result = {'schema': 1, 'command': sys.argv, 'baseline_commit': '1f58fed7c',
              'source_reference': str(REFERENCE), 'source_files': inventory['files'],
              'source_manifest_sha256': inventory['file_manifest_sha256'],
              'source_completeness_established': False, 'full_os_reconstruction': False,
              'required_source_gaps': missing,
              'literal_dirs_gaps_count': len(inventory['literal_dirs_gaps']),
              'inventory_limitations': inventory['limitations'],
              'components': components,
              'provided_scm_library_inputs': {p: sha(REFERENCE / p) for p in PROVIDED_SCM_LIBRARIES},
              'compatibility_fixes': {
                  'services.exe': 'Build original checked sclib/wrlib, local Winreg/svcslib and PnP import library; no SCM implementation patch.',
                  'smss.exe': 'No implementation patch.',
                  'userenv.dll': 'Missing closing parenthesis in SDK comdef.h corrected in disposable build media; original IDL and RSOP prerequisites built.',
                  'userenv-sp3-adapter': 'Post-link exact SP3 name/ordinal map; three PE forwarders to unchanged original ue51sp3.dll. Process-only tests pass; boot integration rejected.',
                  'explorer.exe': 'Original BrowseUI/Shdocvw .src import libraries; seven explicit x86 NONAME stdcall decorations; original shfusion/stockthk/stock/dv2host built. Compiles; shell integration rejected.',
              },
              'remaining_boot_dependencies': ['installed Microsoft Winlogon and LogonUI',
                  'four supplied executive objects for absent exinit.c/systime.c',
                  'installed Microsoft loader, runtime/service DLLs, device drivers and shell components not replaced in the recorded guest'],
              'limitations': ['Import/export presence does not establish full behavioral or security equivalence.',
                  'Compiled candidates without runtime results are not promoted to guest compatibility.',
                  'The provided library list is SCM-specific, not a complete inventory of proprietary inputs to every component.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'components': len(components), 'verified_experiments': len(runtimes),
                      'full_os_reconstruction': False}))


if __name__ == '__main__':
    main()
