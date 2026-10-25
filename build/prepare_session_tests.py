#!/usr/bin/env python3
"""Prepare a separate, ordinary-process native session test target, never Winlogon."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private output required')
    output.mkdir(parents=True, exist_ok=False)
    target = output / 'media/wltests'
    target.mkdir(parents=True, exist_ok=False)
    for name in ('session_engine.c', 'session_engine.h', 'policy.c', 'policy.h', 'state.c', 'state.h'):
        shutil.copy2(ROOT / 'components/winlogon' / name, target / name)
    for name in ('winlogon_session.c', 'guest/session_contract_probe.c', 'guest/session_contract.rc'):
        shutil.copy2(ROOT / 'tests' / name, target / Path(name).name)
    (target / 'sources').write_text('''TARGETNAME=wlsession_test
TARGETPATH=obj
TARGETTYPE=PROGRAM
UMTYPE=console
UMENTRY=main
USE_MSVCRT=1
MSC_WARNING_LEVEL=/W4 /WX
C_DEFINES=-DWIN32 -DNT -DXP25_SESSION_TEST=1 -DXP25_NATIVE_TEST_ENTRY=1
SOURCES=winlogon_session.c session_contract_probe.c session_engine.c policy.c state.c session_contract.rc
UMLIBS=$(SDK_LIB_PATH)\\user32.lib $(SDK_LIB_PATH)\\advapi32.lib $(SDK_LIB_PATH)\\userenv.lib
''')
    (target / 'makefile').write_bytes((ROOT / 'components/winlogon/makefile').read_bytes())
    driver = (ROOT / 'build/native-winlogon-build.cmd').read_text()
    driver = driver.replace('winlogon', 'wltests').replace('XP25_WL_', 'XP25_TEST_')
    driver = driver.replace('XP25_WINLOGON_BUILD_', 'XP25_SESSION_TEST_BUILD_')
    (output / 'media/build.cmd').write_bytes(driver.replace('\n', '\r\n').encode('ascii'))
    command = ['xorriso', '-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-R',
               '-V', 'XP25TEST', '-o', str(output / 'native-tests.iso'), str(output / 'media')]
    subprocess.run(command, check=True)
    files = {str(p.relative_to(output / 'media')): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (output / 'media').rglob('*') if p.is_file()}
    (output / 'manifest.json').write_text(json.dumps({
        'command': command, 'files': files, 'separate_test_executable': True,
        'production_driver_override': False}, indent=2) + '\n')
    print(output / 'native-tests.iso')


if __name__ == '__main__':
    main()
