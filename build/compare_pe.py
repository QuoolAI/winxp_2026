#!/usr/bin/env python3
"""Compare two builds of the same PE image, ignoring only what a relink always
changes: the link time stamp (COFF header), the image checksum, the time stamps
of the export and debug directories, and the signature/age of a CodeView
(NB10 or RSDS) debug record that names the PDB. Every other byte must match.

The output says which of those fields differed and lists any other differing
byte ranges, so "reproducible except for link-time metadata" is a checked claim.

usage: compare_pe.py A B   (exit 0 when the images are equal after normalization)
       compare_pe.py --maps A B A.map B.map
           two links of the same objects: which differing bytes are references
           to code or data that moved (same symbol and offset in both), and
           which are not explained that way
       compare_pe.py --symbols A B A.map B.map
           the same, symbol by symbol wherever the linker placed each one"""
import json
from pathlib import Path
import struct
import sys


def normalized(data):
    data = bytearray(data)
    fields = {}
    pe, = struct.unpack_from('<I', data, 60)
    opt = pe + 24
    optsize, = struct.unpack_from('<H', data, pe + 20)
    nsec, = struct.unpack_from('<H', data, pe + 6)
    headers, = struct.unpack_from('<I', data, opt + 60)
    sections = [struct.unpack_from('<IIII', data, opt + optsize + n * 40 + 8) for n in range(nsec)]

    def offset(rva):
        if rva < headers:
            return rva
        for size, start, rawsize, raw in sections:
            if start <= rva < start + max(size, rawsize) and rva - start < rawsize:
                return raw + rva - start
        return None

    def blank(name, at, length):
        fields[name] = bytes(data[at:at + length]).hex()
        data[at:at + length] = bytes(length)
    blank('coff_time_stamp', pe + 8, 4)
    blank('checksum', opt + 64, 4)
    export_rva, _ = struct.unpack_from('<II', data, opt + 96)
    if export_rva and offset(export_rva) is not None:
        blank('export_time_stamp', offset(export_rva) + 4, 4)
    debug_rva, debug_size = struct.unpack_from('<II', data, opt + 96 + 6 * 8)
    at = offset(debug_rva) if debug_rva else None
    for n in range(debug_size // 28 if at is not None else 0):
        entry = at + n * 28
        blank('debug_%d_time_stamp' % n, entry + 4, 4)
        kind, size, _, raw = struct.unpack_from('<IIII', data, entry + 12)
        if kind == 2 and raw + 4 <= len(data):
            magic = bytes(data[raw:raw + 4])
            if magic == b'NB10':
                blank('codeview_%d_signature_age' % n, raw + 8, 8)
            elif magic == b'RSDS':
                blank('codeview_%d_guid_age' % n, raw + 4, 20)
    return bytes(data), fields


def map_symbols(path, base):
    """{rva: name} of the public symbols of a Microsoft linker .map file."""
    import re
    out = {}
    for line in Path(path).read_text('latin-1').splitlines():
        m = re.match(r'\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s', line)
        if m and int(m.group(2), 16) >= base:
            out[int(m.group(2), 16) - base] = m.group(1)
    return out


def explain(a, b, map_a, map_b):
    """Accounts for every differing byte of two relinks of the same objects: an absolute address at a
    base-relocated position, or the 32-bit displacement of a relative call or jump, whose target is the
    same symbol plus offset in both images, is the same code at another place. Returns the bytes that
    no such reading explains, with the section they are in."""
    import bisect
    images = []
    for data, map_path in ((a, map_a), (b, map_b)):
        pe, = struct.unpack_from('<I', data, 60)
        opt = pe + 24
        base, = struct.unpack_from('<I', data, opt + 28)
        optsize, nsec = struct.unpack_from('<H', data, pe + 20)[0], struct.unpack_from('<H', data, pe + 6)[0]
        sections = [struct.unpack_from('<8sIIII', data, opt + optsize + n * 40) for n in range(nsec)]
        reloc_rva, reloc_size = struct.unpack_from('<II', data, opt + 96 + 5 * 8)
        relocs = set()
        raw_of = lambda rva, sections=sections: next((r + rva - va for _, vs, va, rs, r in sections if va <= rva < va + max(vs, rs) and rva - va < rs), None)
        at, end = raw_of(reloc_rva), raw_of(reloc_rva) + reloc_size
        while at is not None and at + 8 <= end:
            page, size = struct.unpack_from('<II', data, at)
            if not size:
                break
            for i in range(8, size, 2):
                entry, = struct.unpack_from('<H', data, at + i)
                if entry >> 12 == 3:
                    relocs.add(page + (entry & 0xfff))
            at += size
        symbols = map_symbols(map_path, base)
        keys = sorted(symbols)
        rva_of = lambda off, sections=sections: next((va + off - r for _, vs, va, rs, r in sections if r <= off < r + rs), None)

        def name(rva, keys=keys, symbols=symbols):
            i = bisect.bisect_right(keys, rva) - 1
            return (symbols[keys[i]], rva - keys[i]) if i >= 0 else (None, rva)
        images.append({'data': data, 'base': base, 'relocs': relocs, 'name': name, 'rva_of': rva_of, 'sections': sections})
    A, B = images
    explained, unexplained, i = 0, [], 0
    size = min(len(a), len(b))
    while i < size:
        if a[i] == b[i]:
            i += 1
            continue
        done = False
        # A 32-bit field containing this byte that both images relocate, or a rel32 after E8/E9/0F 8x.
        for start in range(i - 3, i + 1):
            ra, rb = A['rva_of'](start), B['rva_of'](start)
            if ra is None or rb is None or start < 0:
                continue
            va, vb = struct.unpack_from('<I', a, start)[0], struct.unpack_from('<I', b, start)[0]
            if ra in A['relocs'] and rb in B['relocs']:
                if A['name'](va - A['base']) == B['name'](vb - B['base']):
                    explained += 4
                    i = start + 4
                    done = True
                    break
            prev_a, prev_b = a[start - 1], b[start - 1]
            if prev_a == prev_b and (prev_a in (0xe8, 0xe9) or (0x80 <= prev_a <= 0x8f and a[start - 2] == 0x0f)):
                ta = (ra + 4 + struct.unpack_from('<i', a, start)[0]) & 0xffffffff
                tb = (rb + 4 + struct.unpack_from('<i', b, start)[0]) & 0xffffffff
                if A['name'](ta) == B['name'](tb):
                    explained += 4
                    i = start + 4
                    done = True
                    break
        if not done:
            ra = A['rva_of'](i)
            section = next((n.rstrip(b'\0').decode() for n, vs, va, rs, r in A['sections'] if r <= i < r + rs), 'headers')
            unexplained.append({'offset': hex(i), 'section': section, 'symbol': A['name'](ra) if ra is not None else None})
            i += 1
    return explained, unexplained


def compare_symbols(a, b, map_a, map_b):
    """Symbol by symbol: the bytes from each public symbol to the next one in image A, against the same
    symbol's bytes in image B (wherever the linker put it). A difference counts as a moved reference when
    both images relocate that position and the address names the same symbol and offset, or when it is
    the displacement of a relative call/jump whose target is the same symbol and offset."""
    import bisect
    images = []
    for data, map_path in ((a, map_a), (b, map_b)):
        pe, = struct.unpack_from('<I', data, 60)
        opt = pe + 24
        base, = struct.unpack_from('<I', data, opt + 28)
        optsize, nsec = struct.unpack_from('<H', data, pe + 20)[0], struct.unpack_from('<H', data, pe + 6)[0]
        sections = [struct.unpack_from('<8sIIII', data, opt + optsize + n * 40) for n in range(nsec)]

        def raw_of(rva, sections=sections):
            return next((r + rva - va for _, vs, va, rs, r in sections if va <= rva < va + rs), None)
        reloc_rva, reloc_size = struct.unpack_from('<II', data, opt + 96 + 5 * 8)
        relocs, at = set(), raw_of(reloc_rva)
        end = at + reloc_size
        while at + 8 <= end:
            page, size = struct.unpack_from('<II', data, at)
            if not size:
                break
            for i in range(8, size, 2):
                entry, = struct.unpack_from('<H', data, at + i)
                if entry >> 12 == 3:
                    relocs.add(page + (entry & 0xfff))
            at += size
        symbols = map_symbols(map_path, base)
        by_name = {n: rva for rva, n in symbols.items()}
        keys = sorted(symbols)

        def name(rva, keys=keys, symbols=symbols):
            i = bisect.bisect_right(keys, rva) - 1
            return (symbols[keys[i]], rva - keys[i]) if i >= 0 else (None, rva)
        images.append({'base': base, 'relocs': relocs, 'name': name, 'raw_of': raw_of, 'by_name': by_name, 'keys': keys,
                       'sections': sections})
    A, B = images
    counts = {'identical': 0, 'identical_except_moved_references': 0, 'different': 0, 'not_in_both': 0}
    different = []
    names = sorted(A['by_name'])
    for name in names:
        ra, rb = A['by_name'][name], B['by_name'].get(name)
        if rb is None:
            counts['not_in_both'] += 1
            continue
        ia = bisect.bisect_right(A['keys'], ra)
        ib = bisect.bisect_right(B['keys'], rb)
        if ia >= len(A['keys']) or ib >= len(B['keys']):
            continue
        length = min(A['keys'][ia] - ra, B['keys'][ib] - rb, 1 << 20)
        oa, ob = A['raw_of'](ra), B['raw_of'](rb)
        if oa is None or ob is None or length <= 0:
            continue                                             # uninitialized data or zero-length labels
        sa, sb = a[oa:oa + length], b[ob:ob + length]
        if sa == sb:
            counts['identical'] += 1
            continue
        k, moved, bad = 0, False, None
        while k < length:
            if sa[k] == sb[k]:
                k += 1
                continue
            ok = False
            for start in range(max(0, k - 3), k + 1):
                if start + 4 > length:
                    continue
                va, vb = struct.unpack_from('<I', sa, start)[0], struct.unpack_from('<I', sb, start)[0]
                if ra + start in A['relocs'] and rb + start in B['relocs'] and A['name'](va - A['base']) == B['name'](vb - B['base']):
                    ok = True
                elif start >= 1 and sa[start - 1] == sb[start - 1] and (sa[start - 1] in (0xe8, 0xe9) or
                                                                       (start >= 2 and 0x80 <= sa[start - 1] <= 0x8f and sa[start - 2] == 0x0f)):
                    ta = (ra + start + 4 + struct.unpack_from('<i', sa, start)[0]) & 0xffffffff
                    tb = (rb + start + 4 + struct.unpack_from('<i', sb, start)[0]) & 0xffffffff
                    ok = A['name'](ta) == B['name'](tb)
                if ok:
                    k = start + 4
                    moved = True
                    break
            if not ok:
                bad = k
                break
        if bad is None:
            counts['identical_except_moved_references'] += 1
        else:
            counts['different'] += 1
            different.append({'symbol': name, 'offset_in_symbol': bad, 'length_compared': length})
    return counts, different


def main():
    if len(sys.argv) == 6 and sys.argv[1] == '--symbols':
        a, b = Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes()
        counts, different = compare_symbols(a, b, sys.argv[4], sys.argv[5])
        print(json.dumps({'a': sys.argv[2], 'b': sys.argv[3], 'symbols': counts, 'different': different[:80]}, indent=1))
        return 0 if not different else 1
    if len(sys.argv) == 6 and sys.argv[1] == '--maps':
        a, b = Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes()
        na, _ = normalized(a)
        nb, _ = normalized(b)
        explained, unexplained = explain(na, nb, sys.argv[4], sys.argv[5])
        from collections import Counter
        result = {'a': sys.argv[2], 'b': sys.argv[3], 'differing_bytes_explained_as_moved_references': explained,
                  'unexplained_bytes': len(unexplained), 'unexplained_by_section': dict(Counter(u['section'] for u in unexplained)),
                  'unexplained_symbols': sorted(set(str(u['symbol'][0]) for u in unexplained if u['symbol']))[:60]}
        print(json.dumps(result, indent=1))
        return 0
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    a, b = (Path(x).read_bytes() for x in sys.argv[1:])
    na, fa = normalized(a)
    nb, fb = normalized(b)
    ranges, start = [], None
    for i in range(max(len(na), len(nb))):
        differ = i >= len(na) or i >= len(nb) or na[i] != nb[i]
        if differ and start is None:
            start = i
        elif not differ and start is not None:
            ranges.append((start, i))
            start = None
    if start is not None:
        ranges.append((start, max(len(na), len(nb))))
    result = {'a': sys.argv[1], 'b': sys.argv[2], 'sizes': [len(a), len(b)],
              'metadata_that_differs': sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k)),
              'other_differing_ranges': [{'offset': hex(s), 'bytes': e - s} for s, e in ranges[:40]],
              'equal_after_normalization': not ranges and len(a) == len(b)}
    print(json.dumps(result, indent=1))
    return 0 if result['equal_after_normalization'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
