"""Conservative PE32 resource editing with byte-preserved executable sections."""
import hashlib
import struct
from inspect_component import PE


def align(value, boundary=4):
    return (value + boundary - 1) & -boundary


def zread(data, offset):
    start = offset
    while struct.unpack_from('<H', data, offset)[0]:
        offset += 2
    return data[start:offset].decode('utf-16-le'), offset + 2


def zwrite(value):
    return value.encode('utf-16-le') + b'\0\0'


def field_read(data, offset):
    value = struct.unpack_from('<H', data, offset)[0]
    if value == 0xffff:
        return struct.unpack_from('<H', data, offset + 2)[0], offset + 4
    return zread(data, offset)


def field_write(value):
    return struct.pack('<HH', 0xffff, value) if isinstance(value, int) else zwrite(value)


class Resources:
    def __init__(self, path):
        self.pe = PE(path)
        self.rva, self.size = self.pe.directory(2)
        self.base = self.pe.offset(self.rva)
        self.entries, self.headers = {}, {}
        self._read(0, ())

    def _read(self, offset, prefix):
        data = self.pe.data
        at = self.base + offset
        header = struct.unpack_from('<IIHHHH', data, at)
        self.headers[prefix] = header[:4]
        for i in range(header[4] + header[5]):
            name, child = struct.unpack_from('<II', data, at + 16 + i * 8)
            if name & 0x80000000:
                start = self.base + (name & 0x7fffffff)
                length = self.pe.u16(start)
                name = data[start + 2:start + 2 + length * 2].decode('utf-16-le')
            key = prefix + (name,)
            if child & 0x80000000:
                self._read(child & 0x7fffffff, key)
            else:
                rva, length, codepage, reserved = struct.unpack_from('<IIII', data, self.base + child)
                start = self.pe.offset(rva)
                if len(key) != 3 or key in self.entries:
                    raise ValueError('unexpected or duplicate resource key')
                self.entries[key] = {'data': data[start:start + length], 'codepage': codepage, 'reserved': reserved}

    def serialize(self, rva):
        tree = {}
        for key, row in self.entries.items():
            node = tree
            for part in key[:-1]:
                node = node.setdefault(part, {})
            node[key[-1]] = row
        output = bytearray()
        leaves, directories, names = [], [], []
        def write_node(node, prefix):
            position = len(output)
            keys = sorted(node, key=lambda key: (not isinstance(key, str), key))
            named = sum(isinstance(key, str) for key in keys)
            output.extend(struct.pack('<IIHHHH', *self.headers.get(prefix, (0, 0, 0, 0)), named, len(keys) - named))
            output.extend(b'\0' * (len(keys) * 8))
            directories.append((position, node, keys, prefix))
            for i, key in enumerate(keys):
                slot = position + 16 + i * 8
                if isinstance(key, str):
                    names.append((slot, key))
                else:
                    struct.pack_into('<I', output, slot, key)
                if len(prefix) == 2:
                    leaves.append((slot + 4, node[key]))
                else:
                    offset = write_node(node[key], prefix + (key,))
                    struct.pack_into('<I', output, slot + 4, 0x80000000 | offset)
            return position
        write_node(tree, ())
        for slot, name in names:
            struct.pack_into('<I', output, slot, 0x80000000 | len(output))
            encoded = name.encode('utf-16-le')
            output.extend(struct.pack('<H', len(encoded) // 2) + encoded)
        output.extend(b'\0' * (align(len(output)) - len(output)))
        payloads = []
        for slot, row in leaves:
            offset = len(output)
            struct.pack_into('<I', output, slot, offset)
            output.extend(b'\0' * 16)
            payloads.append((offset, row))
        for offset, row in payloads:
            output.extend(b'\0' * (align(len(output)) - len(output)))
            struct.pack_into('<IIII', output, offset, rva + len(output), len(row['data']), row['codepage'], row['reserved'])
            output.extend(row['data'])
        return bytes(output)

    def write(self, output):
        pe = self.pe
        data = bytearray(pe.data)
        section_start = pe.opt + pe.u16(pe.pe + 20)
        count = pe.u16(pe.pe + 6)
        containing = [i for i, row in enumerate(pe.sections) if row[0] <= self.rva < row[0] + row[1]]
        if len(containing) != 1:
            raise ValueError('resource section is ambiguous')
        index = containing[0]
        start, size, raw, rawsize = pe.sections[index]
        if start != self.rva:
            raise ValueError('resource directory must start its dedicated section')
        payload = self.serialize(self.rva)
        if len(payload) <= rawsize and len(payload) <= size:
            data[raw:raw + rawsize] = payload + b'\0' * (rawsize - len(payload))
            struct.pack_into('<I', data, section_start + index * 40 + 8, max(len(payload), pe.u32(section_start + index * 40 + 8)))
            mode = 'existing_resource_section'
        elif raw + rawsize == len(data) and start + size == max(row[0] + row[1] for row in pe.sections):
            section_align, file_align = pe.u32(pe.opt + 32), pe.u32(pe.opt + 36)
            length = align(len(payload), file_align)
            data[raw:] = payload + b'\0' * (length - len(payload))
            struct.pack_into('<I', data, section_start + index * 40 + 8, len(payload))
            struct.pack_into('<I', data, section_start + index * 40 + 16, length)
            struct.pack_into('<I', data, pe.opt + 56, align(start + len(payload), section_align))
            struct.pack_into('<I', data, pe.opt + 8, pe.u32(pe.opt + 8) + length - rawsize)
            mode = 'expanded_last_resource_section'
        else:
            header = section_start + count * 40
            first_raw = min(row[2] for row in pe.sections if row[3])
            if header + 40 > first_raw or any(data[header:header + 40]):
                raise ValueError('no spare PE section header; refusing to move executable bytes')
            section_align, file_align = pe.u32(pe.opt + 32), pe.u32(pe.opt + 36)
            new_rva = align(max(row[0] + row[1] for row in pe.sections), section_align)
            payload = self.serialize(new_rva)
            new_raw = align(len(data), file_align)
            length = align(len(payload), file_align)
            data.extend(b'\0' * (new_raw - len(data)))
            data.extend(payload + b'\0' * (length - len(payload)))
            struct.pack_into('<8sIIIIIIHHI', data, header, b'.xp25rs\0', len(payload), new_rva,
                             length, new_raw, 0, 0, 0, 0, 0x40000040)
            struct.pack_into('<H', data, pe.pe + 6, count + 1)
            struct.pack_into('<I', data, pe.opt + 56, align(new_rva + len(payload), section_align))
            struct.pack_into('<I', data, pe.opt + 8, pe.u32(pe.opt + 8) + length)
            struct.pack_into('<I', data, pe.opt + 96 + 2 * 8, new_rva)
            mode = 'additional_readonly_resource_section'
        struct.pack_into('<I', data, pe.opt + 96 + 2 * 8 + 4, len(payload))
        struct.pack_into('<I', data, pe.opt + 64, 0)
        padded = data + (b'\0' if len(data) & 1 else b'')
        checksum = sum(struct.unpack('<' + 'H' * (len(padded) // 2), padded))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        struct.pack_into('<I', data, pe.opt + 64, checksum + len(data))
        output.write_bytes(data)
        result = Resources(output)
        if result.entries != self.entries:
            raise ValueError('resource round-trip differs')
        new = result.pe
        for i, (rva, size, offset, length) in enumerate(pe.sections):
            if i != index or mode == 'additional_readonly_resource_section':
                if pe.data[offset:offset + length] != new.data[offset:offset + length]:
                    raise ValueError('non-resource section bytes changed')
        if pe.imports() != new.imports() or pe.imports(True) != new.imports(True) or pe.exports() != new.exports():
            raise ValueError('executable contract changed')
        if not new.inspect()['checksum_valid']:
            raise ValueError('invalid output checksum')
        return {'mode': mode, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                'code_imports_exports_preserved': True}


def strings(data):
    values, offset = [], 0
    for _ in range(16):
        size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        values.append(data[offset:offset + size * 2].decode('utf-16-le'))
        offset += size * 2
    if any(data[offset:]):
        raise ValueError('unexpected string table tail')
    return values


def string_data(values):
    return b''.join(struct.pack('<H', len(value.encode('utf-16-le')) // 2) + value.encode('utf-16-le') for value in values)


def dialog(data):
    extended = data[:4] == b'\x01\0\xff\xff'
    if extended:
        version, signature, helpid, exstyle, style, count, x, y, cx, cy = struct.unpack_from('<HHIIIHhhhh', data)
        offset = 26
    else:
        style, exstyle, count, x, y, cx, cy = struct.unpack_from('<IIHhhhh', data)
        helpid, offset = 0, 18
    menu, offset = field_read(data, offset)
    cls, offset = field_read(data, offset)
    title, offset = zread(data, offset)
    font = b''
    if style & 0x40:
        start = offset
        offset += 6 if extended else 2
        _, offset = zread(data, offset)
        font = data[start:offset]
    items = []
    for _ in range(count):
        offset = align(offset)
        if extended:
            ih, ie, ist, ix, iy, icx, icy, identifier = struct.unpack_from('<IIIhhhhI', data, offset)
            offset += 24
        else:
            ist, ie, ix, iy, icx, icy, identifier = struct.unpack_from('<IIhhhhH', data, offset)
            ih, offset = 0, offset + 18
        item_cls, offset = field_read(data, offset)
        text, offset = field_read(data, offset)
        extra_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        extra = data[offset:offset + extra_size]
        offset += extra_size
        items.append(dict(help=ih, exstyle=ie, style=ist, x=ix, y=iy, cx=icx, cy=icy,
                          id=identifier, cls=item_cls, text=text, extra=extra))
    return dict(extended=extended, help=helpid, exstyle=exstyle, style=style, x=x, y=y,
                cx=cx, cy=cy, menu=menu, cls=cls, title=title, font=font, items=items)


def dialog_data(row):
    if row['extended']:
        out = bytearray(struct.pack('<HHIIIHhhhh', 1, 0xffff, row['help'], row['exstyle'], row['style'],
                                   len(row['items']), row['x'], row['y'], row['cx'], row['cy']))
    else:
        out = bytearray(struct.pack('<IIHhhhh', row['style'], row['exstyle'], len(row['items']),
                                   row['x'], row['y'], row['cx'], row['cy']))
    out.extend(field_write(row['menu']) + field_write(row['cls']) + zwrite(row['title']) + row['font'])
    for item in row['items']:
        out.extend(b'\0' * (align(len(out)) - len(out)))
        if row['extended']:
            out.extend(struct.pack('<IIIhhhhI', item['help'], item['exstyle'], item['style'],
                                   item['x'], item['y'], item['cx'], item['cy'], item['id']))
        else:
            out.extend(struct.pack('<IIhhhhH', item['style'], item['exstyle'], item['x'], item['y'],
                                   item['cx'], item['cy'], item['id']))
        out.extend(field_write(item['cls']) + field_write(item['text']))
        out.extend(struct.pack('<H', len(item['extra'])) + item['extra'])
    return bytes(out)
