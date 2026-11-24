"""Read-only PE32 inspection for MerlinAI investigations and build checks: sections, imports (including
delay-loaded ones), exports, the file version, and a byte comparison of two builds of one binary.

Nothing here executes or loads the file; malformed input raises PEError."""
import struct

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_DEBUG, DIR_DELAY_IMPORT = 0, 1, 2, 6, 13


class PEError(ValueError):
    pass


class PE:
    def __init__(self, data):
        self.data = bytes(data)
        if len(self.data) < 0x40 or self.data[:2] != b'MZ':
            raise PEError('not an MZ executable')
        self.pe = self.u32(0x3c)
        if self.data[self.pe:self.pe + 4] != b'PE\0\0':
            raise PEError('no PE signature')
        coff = self.pe + 4
        self.machine, self.section_count, self.timestamp = struct.unpack_from('<HHI', self.data, coff)
        optional_size = self.u16(coff + 16)
        self.optional = coff + 20
        if self.u16(self.optional) != 0x10b:
            raise PEError('not a PE32 image')
        self.image_base = self.u32(self.optional + 28)
        self.checksum_offset = self.optional + 64
        count = self.u32(self.optional + 92)
        self.directories = [struct.unpack_from('<II', self.data, self.optional + 96 + 8 * i) for i in range(min(count, 16))]
        self.sections = []
        table = self.optional + optional_size
        for i in range(self.section_count):
            name, vsize, va, rsize, raw = struct.unpack_from('<8sIIII', self.data, table + 40 * i)
            self.sections.append({'name': name.rstrip(b'\0').decode('latin-1'), 'virtual_size': vsize, 'va': va,
                                  'raw_size': rsize, 'raw': raw, 'header': table + 40 * i})

    def u16(self, offset):
        if offset < 0 or offset + 2 > len(self.data):
            raise PEError('truncated')
        return struct.unpack_from('<H', self.data, offset)[0]

    def u32(self, offset):
        if offset < 0 or offset + 4 > len(self.data):
            raise PEError('truncated')
        return struct.unpack_from('<I', self.data, offset)[0]

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def section_of(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['virtual_size'], s['raw_size']):
                return s
        return None

    def offset(self, rva):
        s = self.section_of(rva)
        if not s or rva - s['va'] >= s['raw_size']:
            raise PEError('RVA 0x%x is not in the file' % rva)
        return s['raw'] + rva - s['va']

    def string(self, rva, limit=512):
        start = self.offset(rva)
        end = self.data.find(b'\0', start, start + limit)
        if end < 0:
            raise PEError('unterminated string')
        return self.data[start:end].decode('latin-1')

    def exports(self):
        """{name: rva or 'forwarder text'}; ordinal-only exports are listed as '#<ordinal>'."""
        rva, size = self.directory(DIR_EXPORT)
        if not rva:
            return {}
        d = self.offset(rva)
        base, functions, names, address_table, name_table, ordinal_table = struct.unpack_from('<IIIIII', self.data, d + 16)
        if functions > 65536 or names > functions:
            raise PEError('implausible export table')
        out, named = {}, set()
        for i in range(names):
            name = self.string(self.u32(self.offset(name_table) + 4 * i))
            index = self.u16(self.offset(ordinal_table) + 2 * i)
            target = self.u32(self.offset(address_table) + 4 * index)
            out[name] = self.string(target) if rva <= target < rva + size else target
            named.add(index)
        for index in range(functions):
            if index not in named and self.u32(self.offset(address_table) + 4 * index):
                out['#%d' % (base + index)] = self.u32(self.offset(address_table) + 4 * index)
        return out

    def export_ordinals(self):
        """'#<ordinal>' for every exported function (an import by ordinal resolves against these)."""
        rva, _ = self.directory(DIR_EXPORT)
        if not rva:
            return set()
        d = self.offset(rva)
        base, functions, _, address_table = struct.unpack_from('<IIII', self.data, d + 16)
        if functions > 65536:
            raise PEError('implausible export table')
        return {'#%d' % (base + i) for i in range(functions) if self.u32(self.offset(address_table) + 4 * i)}

    def _thunks(self, rva):
        names, at = [], self.offset(rva)
        for _ in range(65536):
            value = self.u32(at)
            if not value:
                return names
            names.append('#%d' % (value & 0xffff) if value & 0x80000000 else self.string(value + 2))
            at += 4
        raise PEError('unterminated import thunks')

    def imports(self):
        """{dll (lower case): [names]} for ordinary and delay-loaded imports; ordinals as '#<n>'."""
        out = {}
        rva, _ = self.directory(DIR_IMPORT)
        if rva:
            at = self.offset(rva)
            for _ in range(4096):
                original, _, _, name, first = struct.unpack_from('<IIIII', self.data, at)
                if not (original or name or first):
                    break
                out.setdefault(self.string(name).lower(), []).extend(self._thunks(original or first))
                at += 20
        rva, _ = self.directory(DIR_DELAY_IMPORT)
        if rva:
            at = self.offset(rva)
            for _ in range(4096):
                attributes, name, _, _, name_table = struct.unpack_from('<IIIII', self.data, at)
                if not name:
                    break
                fix = 0 if attributes & 1 else self.image_base        # VC6 descriptors hold addresses, not RVAs
                out.setdefault(self.string(name - fix).lower(), []).extend(self._thunks_delay(name_table - fix, fix))
                at += 32
        return out

    def _thunks_delay(self, rva, fix):
        names, at = [], self.offset(rva)
        for _ in range(65536):
            value = self.u32(at)
            if not value:
                return names
            names.append('#%d' % (value & 0xffff) if value & 0x80000000 else self.string(value - fix + 2))
            at += 4
        raise PEError('unterminated delay import thunks')

    def file_version(self):
        """The FileVersion string of the version resource, or None."""
        return self.version_string('FileVersion')

    def version_string(self, name):
        """A string of the version resource (FileVersion, CompanyName, ...), or None."""
        key = name.encode('utf-16-le') + b'\0\0'
        at = self.data.find(key)
        while at >= 6:
            # A String entry: wLength, wValueLength (characters), wType (1 = text), the key, padding, the value.
            length, value_length, kind = struct.unpack_from('<HHH', self.data, at - 6)
            value = at + len(key)
            value += (4 - (value - (at - 6)) % 4) % 4
            if kind == 1 and 0 < value_length <= 256 and value + 2 * value_length <= len(self.data):
                text = self.data[value:value + 2 * value_length].decode('utf-16-le', 'replace').rstrip('\0').strip()
                if text:
                    return text
            at = self.data.find(key, at + 2)
        return None

    def _masked(self):
        """The section bytes with the fields every link changes blanked: the export directory's time stamp, the
        debug directory entries and their CodeView records (time stamp, PDB signature and path)."""
        data = bytearray(self.data)
        ranges = []
        export = self.directory(DIR_EXPORT)[0]
        if export:
            ranges.append((export + 4, 4))
        rva, size = self.directory(DIR_DEBUG)
        if rva:
            ranges.append((rva, size))
            for i in range(size // 28):
                entry = self.offset(rva) + 28 * i
                record_size, record_rva, record_raw = struct.unpack_from('<III', data, entry + 16)
                if record_raw and record_size:
                    data[record_raw:record_raw + record_size] = b'\0' * record_size
        for rva, size in ranges:
            for s in self.sections:
                lo, hi = max(rva, s['va']), min(rva + size, s['va'] + s['raw_size'])
                if lo < hi:
                    start = s['raw'] + lo - s['va']
                    data[start:start + hi - lo] = b'\0' * (hi - lo)
        return data


def compare_builds(installed, rebuilt, ignore_exports=False):
    """Compare two builds of one binary section by section, ignoring what every relink changes (header time
    stamp and checksum, debug directory, CodeView record) and, with ignore_exports, the whole export section
    or range. Returns {'identical': bool, 'differences': [...], 'layout_changed': bool}."""
    a, b = PE(installed), PE(rebuilt)
    differences = []
    names_a = [(s['name'], s['va']) for s in a.sections]
    names_b = [(s['name'], s['va']) for s in b.sections]
    layout_changed = names_a != names_b or a.image_base != b.image_base
    if layout_changed:
        differences.append('section layout differs')
        return {'identical': False, 'differences': differences, 'layout_changed': True}
    # With ignore_exports the export table may grow inside its section's alignment: that section is skipped.
    export_rva = a.directory(DIR_EXPORT)[0]
    skipped = a.section_of(export_rva)['name'] if ignore_exports and export_rva and a.section_of(export_rva) else None
    ma, mb = a._masked(), b._masked()
    for sa, sb in zip(a.sections, b.sections):
        if sa['name'] == skipped:
            continue
        if sa['raw_size'] != sb['raw_size'] or sa['virtual_size'] != sb['virtual_size']:
            differences.append('%s: size %d/%d -> %d/%d' % (sa['name'], sa['raw_size'], sa['virtual_size'],
                                                           sb['raw_size'], sb['virtual_size']))
            continue
        if ma[sa['raw']:sa['raw'] + sa['raw_size']] != mb[sb['raw']:sb['raw'] + sb['raw_size']]:
            differences.append('%s: contents differ' % sa['name'])
    return {'identical': not differences, 'differences': differences, 'layout_changed': False}
