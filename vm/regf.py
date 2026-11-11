#!/usr/bin/env python3
"""Minimal read-only reader for NT registry hive files (regf), used to check
values offline in extracted guest hives. It never writes a hive.
usage: regf.py <hive> <key path suffix> [value name]"""
import struct
import sys


def walk(data):
    """Yield (key path, value name, type, data) for every value; keys without
    values yield (path, None, None, None). Big-data values yield data None."""
    view = memoryview(data)

    def cell(offset):
        return view[0x1000 + offset + 4:]

    def subkeys(offset):
        c = cell(offset)
        kind, count = bytes(c[:2]), struct.unpack_from('<H', c, 2)[0]
        if kind in (b'lf', b'lh'):
            return [struct.unpack_from('<I', c, 4 + 8 * i)[0] for i in range(count)]
        if kind == b'li':
            return [struct.unpack_from('<I', c, 4 + 4 * i)[0] for i in range(count)]
        if kind == b'ri':
            return [k for i in range(count) for k in subkeys(struct.unpack_from('<I', c, 4 + 4 * i)[0])]
        raise ValueError('unknown subkey list %r' % kind)

    def text(raw, ascii_flag):
        raw = bytes(raw)
        return raw.decode('latin-1') if ascii_flag else raw.decode('utf-16-le', 'replace')

    def key(offset, parent):
        c = cell(offset)
        if bytes(c[:2]) != b'nk':
            raise ValueError('not a key cell at %#x' % offset)
        flags, = struct.unpack_from('<H', c, 2)
        nsub, = struct.unpack_from('<I', c, 0x14)
        lsub, = struct.unpack_from('<I', c, 0x1c)
        nval, = struct.unpack_from('<I', c, 0x24)
        lval, = struct.unpack_from('<I', c, 0x28)
        nlen, = struct.unpack_from('<H', c, 0x48)
        name = text(c[0x4c:0x4c + nlen], flags & 0x20)
        path = name if parent is None else parent + '\\' + name
        if nval:
            values = cell(lval)
            for i in range(nval):
                v = cell(struct.unpack_from('<I', values, 4 * i)[0])
                if bytes(v[:2]) != b'vk':
                    raise ValueError('not a value cell')
                vlen, size, offset_or_data, vtype, vflags = struct.unpack_from('<HIIIH', v, 2)
                vname = text(v[0x14:0x14 + vlen], vflags & 1) if vlen else ''
                if size & 0x80000000:
                    raw = struct.pack('<I', offset_or_data)[:size & 0x7fffffff]
                elif size > 16344:
                    raw = None
                else:
                    raw = bytes(cell(offset_or_data)[:size])
                yield path, vname, vtype, raw
        else:
            yield path, None, None, None
        for child in (subkeys(lsub) if nsub else []):
            yield from key(child, path)

    root, = struct.unpack_from('<I', data, 0x24)
    yield from key(root, None)


def values(data, suffix):
    """Values of the first key whose path ends with suffix (case-insensitive)."""
    suffix = suffix.lower()
    found = {}
    for path, name, vtype, raw in walk(data):
        if path.lower().endswith(suffix) and name is not None:
            found[name] = (vtype, raw)
    return found


def string(entry):
    vtype, raw = entry
    return raw.decode('utf-16-le', 'replace').rstrip('\0') if vtype in (1, 2) and raw is not None else None


if __name__ == '__main__':
    found = values(open(sys.argv[1], 'rb').read(), sys.argv[2])
    for name, entry in sorted(found.items()):
        if len(sys.argv) < 4 or name == sys.argv[3]:
            print(repr(name), entry[0], string(entry) if string(entry) is not None else (entry[1] or b'').hex())
