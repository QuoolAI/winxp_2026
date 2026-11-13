#!/usr/bin/env python3
"""Moderate, bounded host load for an XP25 lab run: CPU and disk I/O that compete
with the guest's QEMU process, the way other guests and builds did when the AI
cases failed in Milestone 8.

  --cpus N      N busy processes (each one spins for --busy-ms, then sleeps for
                --idle-ms: a duty cycle, not a full core)
  --io-dir DIR  one writer that writes, fsyncs and removes --io-mb MB files in
                DIR, pausing --io-pause seconds after each (a fresh .work
                directory; only files it created are removed)

The defaults are a moderate load: four processes at a 50 % duty cycle (about
two of the host's twelve cores) and at most 16 MB/s of synchronous writes.
Run ai-old-load-up-01 shows what an unbounded writer does instead: 32 MB/s of
fsync on the volume holding the guest disk slowed the guest by two orders of
magnitude.

It stops by itself after --seconds, or as soon as DIR/stop exists, and writes
DIR/host-load.json with the parameters and what was done.

usage: host_load.py --io-dir DIR [--cpus N] [--busy-ms B] [--idle-ms I] [--seconds S]"""
import argparse
import json
import multiprocessing
import os
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]


def spin(stop, until, busy, idle):
    count = 0
    while time.time() < until and not stop.exists():
        end = time.time() + busy
        while time.time() < end:
            count += 1
        time.sleep(idle)
    return count


def writer(directory, stop, until, megabytes, pause):
    block = os.urandom(1 << 20)
    written, files = 0, 0
    while time.time() < until and not stop.exists():
        path = directory / ('load-%d.bin' % files)
        with open(path, 'wb') as f:
            for _ in range(megabytes):
                f.write(block)
            f.flush()
            os.fsync(f.fileno())
        written += megabytes
        files += 1
        path.unlink()
        time.sleep(pause)
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--io-dir', type=Path, required=True)
    parser.add_argument('--cpus', type=int, default=4)
    parser.add_argument('--busy-ms', type=int, default=50)
    parser.add_argument('--idle-ms', type=int, default=50)
    parser.add_argument('--io-mb', type=int, default=16)
    parser.add_argument('--io-pause', type=float, default=1.0)
    parser.add_argument('--seconds', type=int, default=7200)
    args = parser.parse_args()
    directory = args.io_dir.resolve()
    if not directory.is_relative_to(ROOT / '.work'):
        parser.error('the load directory must be under .work/')
    directory.mkdir(parents=True, exist_ok=False)
    stop, until = directory / 'stop', time.time() + args.seconds
    record = {'cpus': args.cpus, 'busy_ms': args.busy_ms, 'idle_ms': args.idle_ms, 'io_mb': args.io_mb, 'io_pause_s': args.io_pause,
              'io': 'files written, fsynced, removed, then a pause',
              'host_cpus': os.cpu_count(), 'started': time.time(), 'limit_seconds': args.seconds, 'pid': os.getpid()}
    (directory / 'host-load.json').write_text(json.dumps(record, indent=1) + '\n')
    with multiprocessing.Pool(args.cpus + 1) as pool:
        spins = [pool.apply_async(spin, (stop, until, args.busy_ms / 1000, args.idle_ms / 1000)) for _ in range(args.cpus)]
        io = pool.apply_async(writer, (directory, stop, until, args.io_mb, args.io_pause))
        record['spin_iterations'] = [s.get() for s in spins]
        record['megabytes_written'] = io.get()
    record['ended'] = time.time()
    record['ended_by'] = 'stop file' if stop.exists() else 'time limit'
    (directory / 'host-load.json').write_text(json.dumps(record, indent=1) + '\n')


if __name__ == '__main__':
    main()
