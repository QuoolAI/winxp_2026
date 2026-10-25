"""Guards of the interactive-VM configuration tools: refusals before any disk
is opened, stale-probe rejection, guest script hygiene and the hive reader."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import regf

SCRIPTS = ROOT / 'tests/guest/vmconfig'


def run(*args):
    return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, timeout=60)


def hive(values):
    """A one-key regf image: root key 'ROOT' holding REG_SZ values."""
    cells, offset = [], 0x20

    def add(data):
        nonlocal offset
        size = (len(data) + 4 + 7) & ~7
        cells.append(struct.pack('<i', -size) + data + b'\0' * (size - 4 - len(data)))
        at, offset = offset, offset + size
        return at
    entries = []
    for name, value in values.items():
        data = (value + '\0').encode('utf-16-le')
        data_at = add(data)
        vk = b'vk' + struct.pack('<HIIIHH', len(name), len(data), data_at, 1, 1, 0) + name.encode('latin-1')
        entries.append(add(vk))
    vlist = add(b''.join(struct.pack('<I', e) for e in entries))
    name = b'ROOT'
    nk = bytearray(0x4c) + name
    nk[0:2] = b'nk'
    struct.pack_into('<H', nk, 2, 0x20)
    struct.pack_into('<I', nk, 0x24, len(values))
    struct.pack_into('<I', nk, 0x28, vlist)
    struct.pack_into('<H', nk, 0x48, len(name))
    root = offset
    cells.append(struct.pack('<i', -((len(nk) + 4 + 7) & ~7)) + bytes(nk) + b'\0' * (((len(nk) + 4 + 7) & ~7) - 4 - len(nk)))
    base = bytearray(0x1000)
    base[0:4] = b'regf'
    struct.pack_into('<I', base, 0x24, root)
    return bytes(base) + b'\0' * 0x20 + b''.join(cells)


class VmConfigGuards(unittest.TestCase):
    def test_offline_update_refuses_before_opening_a_disk(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            outside = Path(tempfile.gettempdir()) / 'xp25-not-under-work.qcow2'
            cases = [
                (['--disk', outside, '--output', Path(name) / 'a', '--oeminfo', ROOT / 'branding/oeminfo.ini',
                  '--oeminfo-current', '0' * 64], 'rehearsal overlays'),
                (['--disk', Path(name) / 'x.qcow2', '--output', Path(name) / 'b', '--branding', name], 'needs --upgrade-from'),
                (['--disk', Path(name) / 'x.qcow2', '--output', Path(name) / 'c'], 'choose updates or --rollback'),
                (['--disk', Path(name) / 'x.qcow2', '--output', '/tmp/xp25-evidence', '--rollback', 'r.json'], 'under .work'),
            ]
            for args, message in cases:
                with self.subTest(message=message):
                    result = run(ROOT / 'vm/vm_offline_update.py', *args)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)
            self.assertFalse(any((Path(name) / n).exists() for n in 'abc'))

    def test_media_rejects_stale_probe(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            probe = Path(name) / 'probe'
            probe.mkdir()
            (probe / 'oem_probe.exe').write_bytes(b'MZ')
            (probe / 'result.json').write_text(json.dumps({'status': 'compiled_static_checks_passed',
                                                           'source_sha256': '0' * 64, 'executable_sha256': '0' * 64}))
            result = run(ROOT / 'build/prepare_vm_config_media.py', '--probe', probe, '--output', Path(name) / 'media')
            self.assertEqual(result.returncode, 2)
            self.assertIn('stale or unverified', result.stderr)
            self.assertFalse((Path(name) / 'media').exists())

    def test_guest_scripts_are_ascii_and_record_every_step(self):
        before = (SCRIPTS / 'vm-before.cmd').read_text(encoding='ascii')
        for step in ('COPY_EXIT', 'REG_EXPORT_OEM_EXIT', 'REG_EXPORT_NAME_EXIT', 'REG_EXPORT_TCPIP_EXIT',
                     'RESTORE_SCRIPT_COPY_EXIT', 'PROBE_COPY_EXIT', 'PROBE_EXIT', 'REG_MANUFACTURER_EXIT',
                     'REG_MODEL_EXIT', 'RENAME_EXIT', 'REG_HOSTNAME_EXIT', 'XP25_VM_BEFORE_DONE'):
            self.assertIn(step, before)
        self.assertIn('if exist %R% exit /b 3', before)   # never overwrites an earlier backup
        for script in SCRIPTS.glob('*.cmd'):
            script.read_text(encoding='ascii')
        self.assertEqual((ROOT / 'branding/oeminfo.ini').read_bytes(),
                         b'[General]\r\nManufacturer=QuoolAI\r\nModel=Windows XP 25th Anniversary Edition\r\n')

    def test_hive_reader_finds_values(self):
        data = hive({'Manufacturer': 'QuoolAI', 'Model': 'Windows XP 25th Anniversary Edition'})
        found = regf.values(data, 'root')
        self.assertEqual({k: regf.string(v) for k, v in found.items()},
                         {'Manufacturer': 'QuoolAI', 'Model': 'Windows XP 25th Anniversary Edition'})


if __name__ == '__main__':
    unittest.main()
