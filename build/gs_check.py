#!/usr/bin/env python3
"""Check /GS stack-cookie support in a native NT 5.1 build output, from the binary and its PDB 2.00
public symbols: the cookie and its check routine are linked in, the CRT start-up initializer table
(__xc_a .. __xc_z, run by the msvcrt start-up code) holds a pointer to __security_init_cookie, and
how many call sites check a cookie (one per protected function epilogue). Static evidence only: it
does not show the cookie value at run time.

usage: gs_check.py --binary X.dll --pdb X.pdb [--binary ... --pdb ...]   prints one JSON record per binary"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cve_compare_builds import Image, pdb2_public_symbols  # noqa: E402

NAMES = {'cookie': '___security_cookie', 'check': '@__security_check_cookie@4', 'init': '___security_init_cookie',
         'xc_a': '___xc_a', 'xc_z': '___xc_z', 'init_pointer': '_pSecCookieInit'}


def check(binary, pdb):
    data = Path(binary).read_bytes()
    image = Image(data)
    symbols = {s['name']: s['rva'] for s in pdb2_public_symbols(pdb, binary)}
    found = {key: symbols.get(name) for key, name in NAMES.items()}
    record = {'binary': str(binary), 'symbols': found, 'protected_call_sites': 0}
    if None in (found['init_pointer'], found['xc_a'], found['xc_z'], found['init'], found['check'], found['cookie']):
        record['gs'] = False
        return record
    at = image.offset(found['init_pointer'])
    pointer, = struct.unpack_from('<I', data, at)
    record['initializer_in_crt_table'] = found['xc_a'] < found['init_pointer'] < found['xc_z']
    record['initializer_points_to_init'] = pointer == image.base + found['init']
    # Count E8 rel32 calls to the check routine inside executable sections.
    calls = 0
    pe, = struct.unpack_from('<I', data, 60)
    optsize, = struct.unpack_from('<H', data, pe + 20)
    nsec, = struct.unpack_from('<H', data, pe + 6)
    for n in range(nsec):
        vsize, va, rawsize, raw = struct.unpack_from('<IIII', data, image.opt + optsize + n * 40 + 8)
        flags, = struct.unpack_from('<I', data, image.opt + optsize + n * 40 + 36)
        if not flags & 0x20000000:          # IMAGE_SCN_MEM_EXECUTE
            continue
        body = data[raw:raw + min(vsize, rawsize)]
        for i in range(len(body) - 4):
            if body[i] == 0xE8:
                rel, = struct.unpack_from('<i', body, i + 1)
                if va + i + 5 + rel == found['check']:
                    calls += 1
    record['protected_call_sites'] = calls
    record['gs'] = record['initializer_in_crt_table'] and record['initializer_points_to_init'] and calls > 0
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, action='append', required=True)
    parser.add_argument('--pdb', type=Path, action='append', required=True)
    args = parser.parse_args()
    if len(args.binary) != len(args.pdb):
        parser.error('one --pdb per --binary')
    ok = True
    for binary, pdb in zip(args.binary, args.pdb):
        record = check(binary, pdb)
        ok = ok and record['gs']
        print(json.dumps(record))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
