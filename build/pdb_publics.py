#!/usr/bin/env python3
"""Read matching MSF7 public symbols and OMAP addresses for private ABI audits.

Format references: llvm.org/docs/PDB/{MsfFile,DbiStream}.html. Debug metadata
only; this reader neither loads nor modifies any guest executable.
"""
import bisect
import struct
from pathlib import Path
from inspect_component import PE


def public_symbols(pdb, binary):
    data = Path(pdb).read_bytes(); pe = PE(binary)
    if not data.startswith(b'Microsoft C/C++ MSF 7.00'):
        raise ValueError('MSF7 PDB required')
    block, _, count, size, _, block_map = struct.unpack_from('<6I', data, 32)
    if block not in (512, 1024, 2048, 4096) or count * block > len(data):
        raise ValueError('invalid MSF blocks')
    def blocks(ids):
        if any(i >= count for i in ids):raise ValueError('PDB block outside file')
        return b''.join(data[i*block:(i+1)*block] for i in ids)
    ids = struct.unpack_from('<'+'I'*((size+block-1)//block), data, block_map*block)
    directory = blocks(ids)[:size]; stream_count = struct.unpack_from('<I', directory)[0]
    sizes = struct.unpack_from('<'+'I'*stream_count, directory, 4); at = 4+4*stream_count; streams = []
    for n in sizes:
        pages = (n+block-1)//block if n != 0xffffffff else 0
        ids = struct.unpack_from('<'+'I'*pages, directory, at); at += pages*4
        streams.append(blocks(ids)[:n])
    debug, length = pe.directory(6); signatures = []
    for i in range(length//28):
        fields = struct.unpack_from('<IIHHIIII', pe.data, pe.offset(debug)+28*i)
        if fields[4] == 2:
            codeview = pe.data[fields[7]:fields[7]+fields[5]]
            if codeview[:4] == b'RSDS':signatures.append(codeview[4:24])
    info = streams[1]
    if info[12:28]+info[8:12] not in signatures:
        raise ValueError('PDB GUID/age does not match executable')
    dbi = streams[3]; optional = 64+sum(struct.unpack_from('<I', dbi, i)[0] for i in (24,28,32,36,40,52))
    debug_streams = struct.unpack_from('<11H', dbi, optional)
    section_id = debug_streams[10] if debug_streams[10] != 65535 else debug_streams[5]
    headers = streams[section_id]
    sections = [struct.unpack_from('<I', headers, i+12)[0] for i in range(0,len(headers),40)]
    omap = list(struct.iter_unpack('<II', streams[debug_streams[4]])) if debug_streams[4] != 65535 else []
    keys = [row[0] for row in omap]
    symbols = streams[struct.unpack_from('<H', dbi, 20)[0]]; at = 0; result = []
    while at+4 <= len(symbols):
        size, kind = struct.unpack_from('<HH', symbols, at)
        if size < 2 or at+2+size > len(symbols):raise ValueError('invalid symbol record')
        if kind == 0x110e:
            _, offset, segment = struct.unpack_from('<IIH', symbols, at+4)
            name = symbols[at+14:at+size+2].split(bytes([0]))[0].decode('ascii')
            if 0 < segment <= len(sections):
                rva = sections[segment-1]+offset
                if omap:
                    i = bisect.bisect_right(keys,rva)-1
                    if i < 0 or not omap[i][1]:at += size+2; continue
                    rva = omap[i][1]+rva-omap[i][0]
                result.append({'name':name,'rva':rva})
        at += size+2
    return result
