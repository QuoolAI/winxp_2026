#!/usr/bin/env python3
"""Add the exact SP3 UserEnv export contract without changing native executable bytes.

The unavailable CheckXForestLogon and two private implementations are forwarded
to an unchanged, explicitly retained SP3 UserEnv. This is not source replacement
of those three implementations. No security success stubs or ABI guesses.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
from inspect_component import PE

ROOT = Path(__file__).resolve().parents[1]
# SP3 private bindings verified using its matching public PDB plus OMAPFromSrc.
# SP3 ordinal -> original source ordinal. All other 100..158 entries agree.
PRIVATE_ORDINAL_MAP = {117: 118, 118: 140, 131: 117, 140: 131}


def exports(pe):
    rva, size = pe.directory(0)
    at = pe.offset(rva)
    base, count, named, functions, names, ordinals = struct.unpack_from('<IIIIII', pe.data, at + 16)
    addresses = {base + i: pe.u32(pe.offset(functions + i * 4)) for i in range(count) if pe.u32(pe.offset(functions + i * 4))}
    mapping = {pe.string(pe.u32(pe.offset(names + i * 4))): base + pe.u16(pe.offset(ordinals + i * 2)) for i in range(named)}
    return mapping, addresses


def align(value, boundary):
    return (value + boundary - 1) & -boundary


def prepare(native, reference, destination):
    old, sp3 = PE(native), PE(reference)
    a, functions = exports(old)
    b, wanted = exports(sp3)
    if (set(a) != set(b) - {'CheckXForestLogon'} or set(functions) != set(range(100, 207)) or
            set(wanted) != set(range(100, 210)) or b.get('CheckXForestLogon') != 159 or
            set(wanted) - set(b.values()) != set(range(100, 159)) | {200, 201} or
            any(old.exports().values())):
        raise ValueError('unreviewed native/SP3 UserEnv contract')
    if not old.inspect()['checksum_valid'] or not sp3.inspect()['checksum_valid']:
        raise ValueError('input PE checksum invalid')
    data = bytearray(old.data)
    section_table = old.opt + old.u16(old.pe + 20)
    count = old.u16(old.pe + 6)
    header = section_table + count * 40
    if header + 40 > min(s[2] for s in old.sections if s[3]) or any(data[header:header + 40]):
        raise ValueError('no spare section header; executable bytes will not be relocated')
    section_align, file_align = old.u32(old.opt + 32), old.u32(old.opt + 36)
    rva = align(max(s[0] + s[1] for s in old.sections), section_align)
    blob = bytearray(40)
    def pad():
        blob.extend(b'\0' * (align(len(blob), 4) - len(blob)))
    def string(value):
        offset = len(blob)
        blob.extend(value.encode('ascii') + b'\0')
        return rva + offset
    old_at = old.offset(old.directory(0)[0])
    module = string(old.string(old.u32(old_at + 12)))
    targets = {n: functions[PRIVATE_ORDINAL_MAP.get(n, n)] for n in range(100, 159)}
    for name, ordinal in b.items():
        if name in a:
            targets[ordinal] = functions[a[name]]
    forwarding = {159: 'ue51sp3.CheckXForestLogon', 200: 'ue51sp3.#200', 201: 'ue51sp3.#201'}
    for ordinal, target in forwarding.items():
        targets[ordinal] = string(target)
    names = sorted(b)
    name_rvas = {name: string(name) for name in names}
    pad()
    function_table = rva + len(blob)
    blob.extend(struct.pack('<110I', *(targets[n] for n in range(100, 210))))
    name_table = rva + len(blob)
    blob.extend(struct.pack('<' + 'I' * len(names), *(name_rvas[n] for n in names)))
    ordinal_table = rva + len(blob)
    blob.extend(struct.pack('<' + 'H' * len(names), *(b[n] - 100 for n in names)))
    # Preserve original export-directory metadata; replace only its table pointers.
    blob[:12] = old.data[old_at:old_at + 12]
    struct.pack_into('<IIIIIII', blob, 12, module, 100, 110, len(names), function_table, name_table, ordinal_table)
    raw = align(len(data), file_align)
    rawsize = align(len(blob), file_align)
    data.extend(b'\0' * (raw - len(data)))
    data.extend(blob + b'\0' * (rawsize - len(blob)))
    struct.pack_into('<8sIIIIIIHHI', data, header, b'.xp25exp', len(blob), rva, rawsize, raw, 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<H', data, old.pe + 6, count + 1)
    struct.pack_into('<I', data, old.opt + 8, old.u32(old.opt + 8) + rawsize)
    struct.pack_into('<I', data, old.opt + 56, align(rva + len(blob), section_align))
    struct.pack_into('<II', data, old.opt + 96, rva, len(blob))
    struct.pack_into('<I', data, old.opt + 64, 0)
    padded = data + (b'\0' if len(data) & 1 else b'')
    checksum = sum(struct.unpack('<' + 'H' * (len(padded) // 2), padded))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    struct.pack_into('<I', data, old.opt + 64, checksum + len(data))
    destination.write_bytes(data)
    new = PE(destination)
    c, actual = exports(new)
    if c != b or set(actual) != set(wanted) or not new.inspect()['checksum_valid']:
        raise ValueError('SP3 export map or output checksum differs')
    for start, size, offset, length in old.sections:
        if data[offset:offset + length] != old.data[offset:offset + length]:
            raise ValueError('original section bytes changed')
    if old.imports() != new.imports() or old.imports(True) != new.imports(True):
        raise ValueError('native import contract changed')
    for directory in range(1, 16):
        if old.directory(directory) != new.directory(directory):
            raise ValueError('non-export data directory changed')
    for name, ordinal in b.items():
        if name in a and actual[ordinal] != functions[a[name]]:
            raise ValueError('native named function RVA changed')
    if any(actual[n] != functions[PRIVATE_ORDINAL_MAP.get(n, n)] for n in range(100, 159)):
        raise ValueError('verified SP3 private function binding changed')
    for ordinal, target in forwarding.items():
        if new.exports()['#' + str(ordinal)] != target:
            raise ValueError('missing implementation does not forward to its exact SP3 target')
    return {'named_ordinals': b, 'forwarded_implementations': forwarding,
            'original_sections_preserved': True, 'native_function_rvas_preserved': True,
            'private_sp3_to_source_ordinal': PRIVATE_ORDINAL_MAP,
            'imports_and_non_export_directories_preserved': True, 'pe': new.inspect()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    native, reference, output = (p.resolve() for p in (args.native, args.reference, args.output))
    if any(not p.is_relative_to(ROOT / '.work') for p in (native, reference, output)):
        parser.error('inputs and generated outputs must stay private under .work/')
    output.mkdir(parents=True, exist_ok=False)
    result = prepare(native, reference, output / 'userenv.dll')
    shutil.copy2(reference, output / 'ue51sp3.dll')
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    result.update(command=[sys.executable, *sys.argv], native_input=str(native), native_input_sha256=sha(native),
        original_sp3=str(reference), original_sp3_sha256=sha(reference),
        components={'userenv.dll': sha(output / 'userenv.dll'), 'ue51sp3.dll': sha(output / 'ue51sp3.dll')},
        implementation_scope='Native original SP1 functions, full SP3 ordinal map, three standard PE forwarders to unchanged original SP3 implementations.',
        limitations=['Not independent implementation of the three missing SP3 functions.',
            'Original binary licensing/provenance required before an installation image is represented as licensed.',
            'Runtime profile, policy, domain/cross-forest and loader behavior need separate evidence.',
            'Modified native DLL does not retain any original signed-file identity.'])
    (output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'sha256': result['components'], 'named_exports': len(result['named_ordinals'])}))


if __name__ == '__main__':
    main()
