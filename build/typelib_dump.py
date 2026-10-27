#!/usr/bin/env python3
"""Dump interfaces from an MSFT (OLE Automation) type library: IIDs, base
interface, vtable slots and parameter types. Static evidence only; it does not
establish runtime semantics of any method."""
import argparse
import json
from pathlib import Path
import struct
import uuid

VT = {0: 'VT_EMPTY', 2: 'VT_I2', 3: 'VT_I4', 8: 'VT_BSTR', 9: 'VT_DISPATCH',
      10: 'VT_ERROR', 11: 'VT_BOOL', 12: 'VT_VARIANT', 13: 'VT_UNKNOWN',
      17: 'VT_UI1', 18: 'VT_UI2', 19: 'VT_UI4', 22: 'VT_INT', 23: 'VT_UINT',
      24: 'VT_VOID', 25: 'VT_HRESULT', 26: 'VT_PTR', 29: 'VT_USERDEFINED',
      30: 'VT_LPSTR', 31: 'VT_LPWSTR'}
TKIND = ['ENUM', 'RECORD', 'MODULE', 'INTERFACE', 'DISPATCH', 'COCLASS', 'ALIAS', 'UNION']
PARAMFLAGS = {1: 'in', 2: 'out', 4: 'lcid', 8: 'retval', 16: 'opt'}


def parse(data):
    if data[:4] != b'MSFT':
        raise ValueError('not an MSFT type library')
    header = struct.unpack_from('<4s20i', data, 0)
    varflags, typeinfos = header[5], header[8]
    offset = 0x54 + (4 if varflags & 0x100 else 0)
    typeinfo_offsets = struct.unpack_from('<%di' % typeinfos, data, offset)
    offset += 4 * typeinfos
    segments = [struct.unpack_from('<iiii', data, offset + 16 * i)[:2] for i in range(15)]
    seg = dict(zip(('typeinfo', 'impinfo', 'impfiles', 'ref', 'guidhash', 'guid',
                    'namehash', 'name', 'string', 'typedesc', 'arraydesc',
                    'custdata', 'cdguids', 'res0e', 'res0f'), segments))

    def name(off):
        if off < 0:
            return None
        base = seg['name'][0] + off
        length = struct.unpack_from('<i', data, base + 8)[0] & 0xff
        return data[base + 12:base + 12 + length].decode('latin-1')

    def guid(off):
        if off < 0:
            return None
        return str(uuid.UUID(bytes_le=data[seg['guid'][0] + off:seg['guid'][0] + off + 16])).upper()

    def typedesc(value):
        if value < 0:
            return VT.get(value & 0x0fff, hex(value & 0x0fff))
        a, b = struct.unpack_from('<ii', data, seg['typedesc'][0] + value)
        vt = a & 0x7fff
        if vt == 26:
            return 'VT_PTR(' + typedesc(b) + ')'
        if vt == 29:
            return 'VT_USERDEFINED(href=%#x)' % b
        return VT.get(vt, hex(vt))

    result = []
    for index in range(typeinfos):
        base = seg['typeinfo'][0] + 0x64 * index
        f = struct.unpack_from('<19ihh5i', data, base)
        kind, memoffset, celement = f[0] & 0xf, f[1], f[6]
        posguid, flags, nameoff = f[11], f[12], f[13]
        cimpl, cbvft, datatype1, datatype2 = f[19], f[20], f[22], f[23]
        entry = {'index': index, 'kind': TKIND[kind], 'name': name(nameoff), 'guid': guid(posguid),
                 'typeflags': flags, 'vtable_bytes': cbvft, 'implemented_types': cimpl,
                 'datatype1': datatype1, 'inherited_functions': (datatype2 >> 16) & 0xffff,
                 'functions': []}
        if kind in (3, 4, 5) and cimpl and datatype1 >= 0:
            href = struct.unpack_from('<i', data, seg['ref'][0] + datatype1)[0]
            entry['first_reference_href'] = href
        nfuncs = celement & 0xffff
        if nfuncs and memoffset < len(data):
            total = struct.unpack_from('<i', data, memoffset)[0]
            cursor, records = memoffset + 4, []
            for _ in range(nfuncs):
                info, datatype, fflags = struct.unpack_from('<iii', data, cursor)
                vtoff, _size = struct.unpack_from('<hh', data, cursor + 12)
                fkccic = struct.unpack_from('<i', data, cursor + 16)[0]
                nargs, nopt = struct.unpack_from('<hh', data, cursor + 20)
                reclen = info & 0xffff
                params = []
                pbase = cursor + reclen - 12 * nargs
                for p in range(nargs):
                    ptype, pname, pflags = struct.unpack_from('<iii', data, pbase + 12 * p)
                    params.append({'name': name(pname), 'type': typedesc(ptype),
                                   'flags': [v for k, v in PARAMFLAGS.items() if pflags & k]})
                records.append({'vtable_offset': vtoff, 'return': typedesc(datatype),
                                'funckind': fkccic & 7, 'invkind': (fkccic >> 3) & 0xf,
                                'callconv': (fkccic >> 8) & 0xf, 'params': params})
                cursor += reclen
            ids = struct.unpack_from('<%di' % nfuncs, data, memoffset + 4 + total)
            names = struct.unpack_from('<%di' % nfuncs, data, memoffset + 4 + total + 4 * nfuncs)
            for record, memid, noff in zip(records, ids, names):
                record['memid'] = memid
                record['name'] = name(noff)
            entry['functions'] = records
        result.append(entry)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('typelib', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    text = json.dumps(parse(args.typelib.read_bytes()), indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text)


if __name__ == '__main__':
    main()
