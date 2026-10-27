#!/usr/bin/env python3
"""Inspect native i386 PE contracts, including bound and delay import tables.

Static symbol presence is not a boot, security or behavioral compatibility test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


class PE:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.pe = self.u32(60)
        if self.data[self.pe:self.pe + 4] != b'PE\0\0':
            raise ValueError('not a PE image')
        self.opt = self.pe + 24
        if self.u16(self.pe + 4) != 0x14c or self.u16(self.opt) != 0x10b:
            raise ValueError('only native i386 PE32 images are accepted')
        self.base = self.u32(self.opt + 28)
        self.sections = []
        start = self.opt + self.u16(self.pe + 20)
        for n in range(self.u16(self.pe + 6)):
            at = start + n * 40
            size, rva, rawsize, offset = struct.unpack_from('<IIII', self.data, at + 8)
            self.sections.append((rva, max(size, rawsize), offset, rawsize))

    def u16(self, at):
        return struct.unpack_from('<H', self.data, at)[0]

    def u32(self, at):
        return struct.unpack_from('<I', self.data, at)[0]

    def offset(self, rva):
        if rva < self.u32(self.opt + 60):
            return rva
        for start, size, offset, rawsize in self.sections:
            if start <= rva < start + size and rva - start < rawsize:
                return offset + rva - start
        raise ValueError('RVA has no file data: ' + hex(rva))

    def string(self, rva):
        offset = self.offset(rva)
        end = self.data.index(b'\0', offset)
        return self.data[offset:end].decode('ascii')

    def directory(self, index):
        if index >= self.u32(self.opt + 92):
            return 0, 0
        return struct.unpack_from('<II', self.data, self.opt + 96 + index * 8)

    def imports(self, delay=False):
        rva, size = self.directory(13 if delay else 1)
        result = {}
        if not rva:
            return result
        width = 32 if delay else 20
        for n in range(size // width + 1):
            fields = struct.unpack_from('<' + 'I' * (width // 4), self.data, self.offset(rva + n * width))
            if not any(fields):
                break
            if delay:
                relative = bool(fields[0] & 1)
                name, thunk = fields[1], fields[4]
                if not relative:
                    name -= self.base
                    thunk -= self.base
            else:
                name, thunk = fields[3], fields[0] or fields[4]
                relative = True
            symbols = []
            for i in range(65536):
                value = self.u32(self.offset(thunk + i * 4))
                if not value:
                    break
                if value & 0x80000000:
                    symbols.append('#' + str(value & 0xffff))
                else:
                    symbols.append(self.string(value + 2 if relative else value - self.base + 2))
            result[self.string(name).lower()] = symbols
        return result

    def exports(self):
        rva, size = self.directory(0)
        if not rva:
            return {}
        at = self.offset(rva)
        base, count, named, functions, names, ordinals = struct.unpack_from('<IIIIII', self.data, at + 16)
        result = {}
        for i in range(count):
            value = self.u32(self.offset(functions + i * 4))
            if value:
                result['#' + str(base + i)] = self.string(value) if rva <= value < rva + size else None
        for i in range(named):
            name = self.string(self.u32(self.offset(names + i * 4)))
            ordinal = base + self.u16(self.offset(ordinals + i * 2))
            if '#' + str(ordinal) in result:
                result[name] = result['#' + str(ordinal)]
        return result

    def inspect(self):
        data = bytearray(self.data)
        data[self.opt + 64:self.opt + 68] = b'\0' * 4
        if len(data) & 1:
            data.append(0)
        checksum = sum(struct.unpack('<' + 'H' * (len(data) // 2), data))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum += len(self.data)
        return {'path': str(self.path.resolve()), 'sha256': hashlib.sha256(self.data).hexdigest(),
                'bytes': len(self.data), 'machine': 'i386', 'image_version': [self.u16(self.opt + 44), self.u16(self.opt + 46)],
                'subsystem': self.u16(self.opt + 68), 'checksum_stored': hex(self.u32(self.opt + 64)),
                'checksum_recomputed': hex(checksum), 'checksum_valid': checksum == self.u32(self.opt + 64),
                'imports': self.imports(), 'delay_imports': self.imports(True), 'exports': self.exports()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--modules', type=Path, help='offline extracted guest system32 directory')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    native = PE(args.binary).inspect()
    result = {'native': native, 'limitation': 'Direct/delay export presence only; forwarder targets and dynamic lookup behavior need runtime tests.'}
    if args.reference:
        old = PE(args.reference).inspect()
        result['reference'] = old
        for kind in ('imports', 'delay_imports'):
            a = {(dll, symbol) for dll, symbols in native[kind].items() for symbol in symbols}
            b = {(dll, symbol) for dll, symbols in old[kind].items() for symbol in symbols}
            result[kind + '_difference'] = {'native_only': sorted(a - b), 'reference_only': sorted(b - a)}
    if args.modules:
        modules = {p.name.lower(): p for p in args.modules.iterdir() if p.is_file()}
        missing = []
        for kind in ('imports', 'delay_imports'):
            for dll, symbols in native[kind].items():
                exports = PE(modules[dll]).exports() if dll in modules else {}
                missing += [[kind, dll, symbol] for symbol in symbols if symbol not in exports]
        result['missing_guest_exports'] = missing
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'binary': args.binary.name, 'sha256': native['sha256'],
                      'checksum_valid': native['checksum_valid'],
                      'missing_guest_exports': result.get('missing_guest_exports', 'not_checked')}))
    return 0 if native['checksum_valid'] and not result.get('missing_guest_exports') else 2


if __name__ == '__main__':
    raise SystemExit(main())
