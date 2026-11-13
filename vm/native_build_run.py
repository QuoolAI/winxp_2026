#!/usr/bin/env python3
"""Run one native build in the private build VM from start to frozen disk.

It starts a disposable overlay of the frozen build image with the prepared
media (vm/native_build_lab.py), types the build command into the guest's Run
dialog until the build reports that it started (keys can be lost while the
desktop is still loading; the driver refuses to run twice), waits for the
build's exit marker on COM1, shuts the guest down and freezes the disk
(vm/xp_lab.py). The exit marker value is the driver's verdict only: the
collector still has to check native.log and the binaries.

usage: native_build_run.py --name RUN --base FROZEN_BUILD_DISK --media ISO --prefix XP25_AI_BUILD
       (waits for <prefix>_STARTED and <prefix>_EXIT=<n>; XP25_KEXPORT uses _STARTED / _BUILD_EXIT)"""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / '.work/boot-debug-20261022'


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--name', required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--started', required=True, help='COM1 text the build driver prints first')
    parser.add_argument('--exit-marker', required=True, help='COM1 marker name whose =<n> value is the build result')
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    run = ARTIFACTS / args.name
    subprocess.run([sys.executable, str(ROOT / 'vm/native_build_lab.py'), '--name', args.name, '--base', str(args.base),
                    '--media', str(args.media)], check=True)
    lab = [sys.executable, str(ROOT / 'vm/xp_lab.py'), str(run)]

    def serial():
        path = run / 'serial.log'
        return path.read_bytes().decode('latin-1') if path.exists() else ''
    command = 'cmd /c D:\\build.cmd C:\\xpout\\' + args.name
    deadline = time.time() + args.timeout
    time.sleep(60)
    attempts = 0
    while args.started not in serial():
        if attempts >= 8 or time.time() > deadline:
            raise SystemExit('the build did not start; the run is left for inspection: ' + str(run))
        subprocess.run(lab + ['run', command], check=True, capture_output=True)
        attempts += 1
        for _ in range(45):
            if args.started in serial():
                break
            time.sleep(1)
    pattern = re.compile(re.escape(args.exit_marker) + r'=(-?\d+)')
    while not pattern.search(serial()):
        if time.time() > deadline:
            raise SystemExit('the build did not finish in time; the run is left for inspection: ' + str(run))
        time.sleep(3)
    code = int(pattern.search(serial()).group(1))
    time.sleep(3)
    subprocess.run(lab + ['shutdown'], check=True, capture_output=True)
    subprocess.run(lab + ['finish'], check=True, capture_output=True)
    print('%s %s=%d run-attempts=%d' % (run, args.exit_marker, code, attempts))
    return 0 if code == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
