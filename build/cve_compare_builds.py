#!/usr/bin/env python3
"""Compare the PE images of a Milestone 8.2 control build, a patched build and the
binary installed in the image.

  reproduce INSTALLED CONTROL
      Equal after build/compare_pe.py's link-metadata normalization and after the
      2-byte hints in front of imported names are masked. Hints are the import
      library's export index at link time (they only speed up the loader's name
      lookup) and change whenever a later build republishes an import library.

  symbols A A.pdb B B.pdb OUTPUT_DIR
      Symbol by symbol (build/compare_pe.py --symbols, with map files written from
      the PDBs' public symbols): which functions differ beyond references that only
      moved. For a patch, exactly the patched functions should be listed.

Prints JSON; exit 0 when the comparison holds (reproduce) or completes (symbols)."""
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
import compare_pe  # noqa: E402
from pdb_publics import public_symbols  # noqa: E402


class Image:
    def __init__(self, data):
        self.data = data
        pe, = struct.unpack_from('<I', data, 60)
        self.opt = pe + 24
        self.base, = struct.unpack_from('<I', data, self.opt + 28)
        optsize, = struct.unpack_from('<H', data, pe + 20)
        nsec, = struct.unpack_from('<H', data, pe + 6)
        self.sections = [struct.unpack_from('<IIII', data, self.opt + optsize + n * 40 + 8) for n in range(nsec)]

    def directory(self, index):
        return struct.unpack_from('<II', self.data, self.opt + 96 + 8 * index)

    def offset(self, rva):
        for size, va, rawsize, raw in self.sections:
            if va <= rva < va + max(size, rawsize) and rva - va < rawsize:
                return raw + rva - va
        return None


def hint_offsets(data):
    """File offsets of the hint words of every by-name import, ordinary and delay-loaded."""
    image, found = Image(data), []

    def names(table_rva):
        at = image.offset(table_rva)
        while at is not None:
            entry, = struct.unpack_from('<I', data, at)
            if not entry:
                break
            if not entry & 0x80000000:
                hint = image.offset(entry)
                if hint is not None:
                    found.append(hint)
            at += 4
    rva, size = image.directory(1)
    at = image.offset(rva) if rva else None
    while at is not None:
        original, _, _, name, first = struct.unpack_from('<IIIII', data, at)
        if not (original or name or first):
            break
        names(original or first)
        at += 20
    rva, size = image.directory(13)
    at = image.offset(rva) if rva else None
    while at is not None:
        attributes, name, _, _, table = struct.unpack_from('<IIIII', data, at)[:5]
        if not name:
            break
        names(table if attributes & 1 else table - image.base)
        at += 32
    return found


def reproduce(installed, control):
    a, b = Path(installed).read_bytes(), Path(control).read_bytes()
    na, fa = compare_pe.normalized(a)
    nb, fb = compare_pe.normalized(b)
    na, nb = bytearray(na), bytearray(nb)
    hints_a, hints_b = hint_offsets(a), hint_offsets(b)
    for offsets, data in ((hints_a, na), (hints_b, nb)):
        for offset in offsets:
            data[offset:offset + 2] = b'\0\0'
    differing_hints = sum(1 for x, y in zip(hints_a, hints_b) if a[x:x + 2] != b[y:y + 2])
    remaining = [i for i in range(min(len(na), len(nb))) if na[i] != nb[i]]
    result = {'installed': str(installed), 'control': str(control), 'sizes': [len(a), len(b)],
              'metadata_that_differs': sorted(k for k in fa if fa[k] != fb.get(k)),
              'import_hints': len(hints_a), 'import_hints_that_differ': differing_hints,
              'same_hint_positions': hints_a == hints_b, 'other_differing_bytes': len(remaining),
              'first_other_offsets': [hex(i) for i in remaining[:20]]}
    result['reproduced'] = len(a) == len(b) and hints_a == hints_b and not remaining
    return result


PDB2 = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0'


def pdb2_public_symbols(pdb, binary):
    """Public symbols of a PDB 2.00 ("JG") file, as the NT 5.1 build tools write them:
    1 KB pages with 16-bit page numbers, a DBI stream with the new header, and S_PUB32
    (0x1009) records with length-prefixed names. In that format the name of a
    S_PROCREF/S_DATAREF/S_LPROCREF record follows the record, outside its length, padded
    to four bytes."""
    data = Path(pdb).read_bytes()
    if not data.startswith(PDB2):
        raise ValueError('PDB 2.00 required')
    at = len(PDB2)
    page, _, _ = struct.unpack_from('<IHH', data, at)
    root_size, _ = struct.unpack_from('<II', data, at + 8)
    root_pages = struct.unpack_from('<%dH' % ((root_size + page - 1) // page), data, at + 16)
    root = b''.join(data[p * page:(p + 1) * page] for p in root_pages)[:root_size]
    count, = struct.unpack_from('<H', root, 0)
    sizes = [struct.unpack_from('<I', root, 4 + 8 * i)[0] for i in range(count)]
    at, streams = 4 + 8 * count, []
    for size in sizes:
        pages = (size + page - 1) // page if size != 0xffffffff else 0
        ids = struct.unpack_from('<%dH' % pages, root, at)
        at += 2 * pages
        streams.append(b''.join(data[p * page:(p + 1) * page] for p in ids)[:size] if pages else b'')
    dbi = streams[3]
    if struct.unpack_from('<i', dbi, 0)[0] != -1:
        raise ValueError('old DBI header')
    records = streams[struct.unpack_from('<H', dbi, 20)[0]]
    sections = [va for _, va, _, _ in Image(Path(binary).read_bytes()).sections]
    at, result = 0, []
    while at + 4 <= len(records):
        size, kind = struct.unpack_from('<HH', records, at)
        if size < 2:
            raise ValueError('invalid symbol record')
        if kind == 0x1009:
            _, offset, segment = struct.unpack_from('<IIH', records, at + 4)
            length = records[at + 14]
            name = records[at + 15:at + 15 + length].decode('latin-1')
            if 0 < segment <= len(sections):
                result.append({'name': name, 'rva': sections[segment - 1] + offset})
        at += size + 2
        if kind in (0x400, 0x401, 0x403):
            at = (at + 1 + records[at] + 3) & ~3
    return result


def pdb2_streams(pdb):
    data = Path(pdb).read_bytes()
    at = len(PDB2)
    page, _, _ = struct.unpack_from('<IHH', data, at)
    root_size, _ = struct.unpack_from('<II', data, at + 8)
    root_pages = struct.unpack_from('<%dH' % ((root_size + page - 1) // page), data, at + 16)
    root = b''.join(data[p * page:(p + 1) * page] for p in root_pages)[:root_size]
    count, = struct.unpack_from('<H', root, 0)
    sizes = [struct.unpack_from('<I', root, 4 + 8 * i)[0] for i in range(count)]
    at, streams = 4 + 8 * count, []
    for size in sizes:
        pages = (size + page - 1) // page if size != 0xffffffff else 0
        ids = struct.unpack_from('<%dH' % pages, root, at)
        at += 2 * pages
        streams.append(b''.join(data[p * page:(p + 1) * page] for p in ids)[:size] if pages else b'')
    return streams


def pdb2_contributions(pdb, binary):
    """[(rva, end, 'object (library)')] from the DBI section contributions (version 6.0
    entries of 28 bytes) and module records of a PDB 2.00 file."""
    dbi = pdb2_streams(pdb)[3]
    modi_size, sc_size = struct.unpack_from('<II', dbi, 24)
    modules, at, modi = [], 0, dbi[64:64 + modi_size]
    while at < len(modi):
        end = modi.index(b'\0', at + 64)
        end2 = modi.index(b'\0', end + 1)
        name, library = modi[at + 64:end].decode('latin-1'), modi[end + 1:end2].decode('latin-1')
        modules.append(name if name == library else '%s (%s)' % (name, library.split('\\')[-1]))
        at = (end2 + 1 + 3) & ~3
    sc = dbi[64 + modi_size:64 + modi_size + sc_size]
    if struct.unpack_from('<I', sc, 0)[0] != 0xeffe0000 + 19970605:
        raise ValueError('unexpected section contribution version')
    sections = [va for _, va, _, _ in Image(Path(binary).read_bytes()).sections]
    result = []
    for at in range(4, len(sc) - 27, 28):
        section, _, offset, size, _, module = struct.unpack_from('<HHIIIH', sc, at)
        if 0 < section <= len(sections) and module < len(modules):
            result.append((sections[section - 1] + offset, sections[section - 1] + offset + size, modules[module]))
    return sorted(result)


def write_map(pdb, binary, path):
    image = Image(Path(binary).read_bytes())
    reader = pdb2_public_symbols if Path(pdb).read_bytes()[:len(PDB2)] == PDB2 else public_symbols
    rows = sorted(reader(pdb, binary), key=lambda s: s['rva'])
    with open(path, 'w') as f:
        f.write(' Address         Publics by Value              Rva+Base       Lib:Object\n\n')
        for symbol in rows:
            f.write(' 0001:%08x       %-40s %08x f   generated-from-pdb\n' % (symbol['rva'], symbol['name'],
                                                                         symbol['rva'] + image.base))
    return len(rows)


def symbols(a, pdb_a, b, pdb_b, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    count_a = write_map(pdb_a, a, output / 'a.map')
    count_b = write_map(pdb_b, b, output / 'b.map')
    counts, different = compare_pe.compare_symbols(Path(a).read_bytes(), Path(b).read_bytes(), output / 'a.map', output / 'b.map')
    rows_b = [line.split() for line in (output / 'b.map').read_text().splitlines()[2:]]
    names_a = {line.split()[1] for line in (output / 'a.map').read_text().splitlines()[2:]}
    names_b = {row[1] for row in rows_b}
    result = {'a': str(a), 'b': str(b), 'public_symbols': [count_a, count_b], 'counts': counts,
              'different': different, 'only_in_a': sorted(names_a - names_b), 'only_in_b': sorted(names_b - names_a)}
    if Path(pdb_b).read_bytes()[:len(PDB2)] == PDB2:
        import bisect
        contributions = pdb2_contributions(pdb_b, b)
        starts = [c[0] for c in contributions]
        rva_b = {row[1]: int(row[0].split(':')[1], 16) for row in rows_b}

        def module(name):
            rva = rva_b.get(name)
            i = bisect.bisect_right(starts, rva) - 1 if rva is not None else -1
            return contributions[i][2] if i >= 0 and rva < contributions[i][1] else 'linker or none'
        by_module = {}
        for row in different:
            row['module'] = module(row['symbol'])
            by_module.setdefault(row['module'], []).append(row['symbol'])
        result['different_by_module'] = {m: {'count': len(s), 'symbols': s[:12]} for m, s in sorted(by_module.items())}
    return result


def main():
    if len(sys.argv) == 4 and sys.argv[1] == 'reproduce':
        result = reproduce(sys.argv[2], sys.argv[3])
        print(json.dumps(result, indent=1))
        return 0 if result['reproduced'] else 1
    if len(sys.argv) == 7 and sys.argv[1] == 'symbols':
        print(json.dumps(symbols(*sys.argv[2:]), indent=1))
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
