#!/usr/bin/env python3
"""Offline thread/wait analysis of a raw physical-memory image of an NT 5.1 x86 guest.

Capture with QMP while paused: `hmp info registers` (for CR3/CR4) and
`hmp pmemsave 0 SIZE FILE`. The matching kernel .map supplies PsActiveProcessHead.
Structure offsets are the NT 5.1 x86 layouts; each is cross-checked against live
data (CID/PID, user trap-frame selectors, list links) and failures are reported.
Read-only evidence: it never writes guest memory.
"""
import argparse
import json
from pathlib import Path
import re
import struct

WAIT_REASONS = ['Executive', 'FreePage', 'PageIn', 'PoolAllocation', 'DelayExecution', 'Suspended',
                'UserRequest', 'WrExecutive', 'WrFreePage', 'WrPageIn', 'WrPoolAllocation',
                'WrDelayExecution', 'WrSuspended', 'WrUserRequest', 'WrEventPair', 'WrQueue',
                'WrLpcReceive', 'WrLpcReply', 'WrVirtualMemory', 'WrPageOut', 'WrRendezvous']
OBJECT_TYPES = {0: 'NotificationEvent', 1: 'SynchronizationEvent', 2: 'Mutant', 3: 'Process', 4: 'Queue',
                5: 'Semaphore', 6: 'Thread', 8: 'NotificationTimer', 9: 'SynchronizationTimer'}


class Memory:
    def __init__(self, image, cr4):
        self.data = Path(image).read_bytes()
        self.pae = bool(cr4 & 0x20)

    def phys(self, address, size):
        if address + size > len(self.data):
            raise ValueError('physical address outside image: %#x' % address)
        return self.data[address:address + size]

    def p32(self, address):
        return struct.unpack('<I', self.phys(address, 4))[0]

    def translate(self, cr3, va):
        if self.pae:
            pdpte = struct.unpack('<Q', self.phys((cr3 & ~0x1f) + ((va >> 30) & 3) * 8, 8))[0]
            if not pdpte & 1:
                return None
            pde = struct.unpack('<Q', self.phys((pdpte & 0xffffff000) + ((va >> 21) & 0x1ff) * 8, 8))[0]
            if not pde & 1:
                return None
            if pde & 0x80:
                return (pde & 0xfffe00000) | (va & 0x1fffff)
            pte = struct.unpack('<Q', self.phys((pde & 0xffffff000) + ((va >> 12) & 0x1ff) * 8, 8))[0]
            return (pte & 0xffffff000) | (va & 0xfff) if pte & 1 else None
        pde = self.p32((cr3 & ~0xfff) + (va >> 22) * 4)
        if not pde & 1:
            return None
        if pde & 0x80:
            return (pde & 0xffc00000) | (va & 0x3fffff)
        pte = self.p32((pde & ~0xfff) + ((va >> 12) & 0x3ff) * 4)
        return (pte & ~0xfff) | (va & 0xfff) if pte & 1 else None

    def read(self, cr3, va, size):
        out = b''
        while size:
            chunk = min(size, 0x1000 - (va & 0xfff))
            pa = self.translate(cr3, va)
            if pa is None:
                raise ValueError('not present: %#x' % va)
            out += self.phys(pa, chunk)
            va += chunk
            size -= chunk
        return out

    def u32(self, cr3, va):
        return struct.unpack('<I', self.read(cr3, va, 4))[0]

    def unicode(self, cr3, va):
        length, _, buffer = struct.unpack('<HHI', self.read(cr3, va, 8))
        return self.read(cr3, buffer, length).decode('utf-16-le', errors='replace') if length and buffer else ''


def object_name(m, cr3, body):
    header = body - 0x18
    try:
        offset = m.read(cr3, header + 0xc, 1)[0]
        return m.unicode(cr3, header - offset + 4) if offset else None
    except ValueError:
        return None


def modules(m, cr3, peb):
    result = []
    ldr = m.u32(cr3, peb + 0xc)
    head = ldr + 0xc
    node = m.u32(cr3, head)
    for _ in range(256):
        if node == head:
            break
        result.append({'base': m.u32(cr3, node + 0x18), 'size': m.u32(cr3, node + 0x20),
                       'name': m.unicode(cr3, node + 0x2c)})
        node = m.u32(cr3, node)
    return result


def exports(m, cr3, module):
    base = module['base']
    try:
        pe = base + m.u32(cr3, base + 0x3c)
        rva, size = struct.unpack('<II', m.read(cr3, pe + 0x78, 8))
        if not rva:
            return []
        count, names, functions, names_rva, ordinals = struct.unpack('<5I', m.read(cr3, base + rva + 0x14, 20))
        result = []
        for i in range(names):
            name_rva = m.u32(cr3, base + names_rva + 4 * i)
            ordinal = struct.unpack('<H', m.read(cr3, base + ordinals + 2 * i, 2))[0]
            raw = m.read(cr3, base + name_rva, 64).split(b'\0')[0].decode(errors='replace')
            result.append((m.u32(cr3, base + functions + 4 * ordinal), raw))
        return sorted(result)
    except ValueError:
        return []


def symbolize(address, mods, cache, m, cr3):
    for module in mods:
        if module['base'] <= address < module['base'] + module['size']:
            rva = address - module['base']
            if module['name'] not in cache:
                cache[module['name']] = exports(m, cr3, module)
            best = None
            for export_rva, name in cache[module['name']]:
                if export_rva <= rva:
                    best = (export_rva, name)
            if best and rva - best[0] < 0x2000:
                return '%s!%s+%#x' % (module['name'], best[1], rva - best[0])
            return '%s+%#x' % (module['name'], rva)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--registers', type=Path, required=True, help='HMP info registers output')
    parser.add_argument('--kernel-map', type=Path, required=True)
    parser.add_argument('--kernel-base', type=lambda v: int(v, 0), default=0x80a02000)
    parser.add_argument('--process', action='append', default=[], help='image names to expand (default: all non-system)')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    registers = args.registers.read_text()
    cr3 = int(re.search(r'CR3=([0-9a-fA-F]+)', registers)[1], 16)
    cr4 = int(re.search(r'CR4=([0-9a-fA-F]+)', registers)[1], 16)
    match = re.search(r'_PsActiveProcessHead\s+([0-9a-fA-F]{8})', args.kernel_map.read_text())
    head = int(match[1], 16) - 0x400000 + args.kernel_base
    m = Memory(args.image, cr4)
    report = {'cr3': hex(cr3), 'pae': m.pae, 'processes': [], 'checks_failed': []}
    node = m.u32(cr3, head)
    for _ in range(256):
        if node == head:
            break
        eprocess = node - 0x88
        pid = m.u32(cr3, eprocess + 0x84)
        name = m.read(cr3, eprocess + 0x174, 16).split(b'\0')[0].decode(errors='replace')
        directory = m.u32(cr3, eprocess + 0x18)
        entry = {'pid': pid, 'name': name, 'eprocess': hex(eprocess), 'cr3': hex(directory)}
        report['processes'].append(entry)
        node = m.u32(cr3, node)
        wanted = [p.lower() for p in args.process]
        if (wanted and name.lower() not in wanted) or (not wanted and pid in (0, 4)):
            continue
        peb = m.u32(cr3, eprocess + 0x1b0)
        try:
            mods = modules(m, directory, peb)
        except ValueError as error:
            mods = []
            report['checks_failed'].append('%s modules: %s' % (name, error))
        entry['modules'] = [{'name': x['name'], 'base': hex(x['base']), 'size': x['size']} for x in mods]
        cache, threads = {}, []
        thread_head = eprocess + 0x190
        link = m.u32(cr3, thread_head)
        for _ in range(512):
            if link == thread_head:
                break
            ethread = link - 0x22c
            link = m.u32(cr3, link)
            cid_process, cid_thread = struct.unpack('<II', m.read(cr3, ethread + 0x1ec, 8))
            if cid_process != pid:
                report['checks_failed'].append('%s thread %#x CID process %d' % (name, ethread, cid_process))
                continue
            state = m.read(cr3, ethread + 0x2d, 1)[0]
            reason = m.read(cr3, ethread + 0x5b, 1)[0]
            thread = {'tid': cid_thread, 'state': state, 'wait_reason': WAIT_REASONS[reason] if reason < len(WAIT_REASONS) else reason,
                      'start': None, 'waits': [], 'user_frames': [], 'stack_scan': []}
            win32_start = m.u32(cr3, ethread + 0x228)
            thread['start'] = symbolize(win32_start, mods, cache, m, directory) or hex(win32_start)
            if state == 5:
                block = m.u32(cr3, ethread + 0x5c)
                for _ in range(8):
                    if not block:
                        break
                    obj = m.u32(cr3, block + 0xc)
                    kind = m.read(cr3, obj, 1)[0]
                    thread['waits'].append({'object': hex(obj), 'type': OBJECT_TYPES.get(kind, kind),
                                            'signal_state': struct.unpack('<i', m.read(cr3, obj + 4, 4))[0],
                                            'name': object_name(m, cr3, obj)})
                    nxt = m.u32(cr3, block + 0x10)
                    if nxt == block or nxt == m.u32(cr3, ethread + 0x5c):
                        break
                    block = nxt
            initial = m.u32(cr3, ethread + 0x18)
            frame = initial - 0x210 - 0x8c
            try:
                ebp, eip, cs, esp = (m.u32(cr3, frame + 0x60), m.u32(cr3, frame + 0x68),
                                     m.u32(cr3, frame + 0x6c) & 0xffff, m.u32(cr3, frame + 0x74))
                if cs != 0x1b:
                    report['checks_failed'].append('%s tid %d user CS %#x' % (name, cid_thread, cs))
                else:
                    thread['user_frames'].append(symbolize(eip, mods, cache, m, directory) or hex(eip))
                    for _ in range(32):
                        if not ebp or ebp >= 0x80000000:
                            break
                        saved, ret = struct.unpack('<II', m.read(directory, ebp, 8))
                        thread['user_frames'].append(symbolize(ret, mods, cache, m, directory) or hex(ret))
                        if saved <= ebp:
                            break
                        ebp = saved
                    teb = m.u32(cr3, ethread + 0x20)
                    limit = min(m.u32(directory, teb + 4), esp + 0x2000)
                    for address in range(esp, limit, 4):
                        try:
                            value = m.u32(directory, address)
                        except ValueError:
                            break
                        text = symbolize(value, mods, cache, m, directory)
                        if text and len(thread['stack_scan']) < 40:
                            thread['stack_scan'].append(text)
            except ValueError as error:
                thread['user_frames'].append('unreadable: %s' % error)
            threads.append(thread)
        entry['threads'] = threads
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'processes': [(p['pid'], p['name']) for p in report['processes']],
                      'checks_failed': report['checks_failed']}))


if __name__ == '__main__':
    main()
