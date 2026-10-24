"""Protect the SP3 ordinal ABI and original native code during compatibility work."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
sys.path.insert(0, str(ROOT / 'vm'))
from inspect_component import PE
from userenv_sp3_compat import prepare, exports
from extension_results import group
from package_verified_desktop import verify_report, verify_run
import hashlib
import json


class ExtensionGuards(unittest.TestCase):
    def test_image_rejects_stale_runtime_evidence(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            directory = Path(name)
            evidence = directory / 'serial.log'; evidence.write_bytes(b'pass')
            report = {'passed': True, 'checks': {'runtime': True},
                      'evidence_sha256': {'serial.log': hashlib.sha256(evidence.read_bytes()).hexdigest()}}
            (directory / 'report.json').write_text(json.dumps(report))
            verify_report(directory, 'report.json')
            evidence.write_bytes(b'changed after acceptance')
            with self.assertRaisesRegex(ValueError, 'stale runtime evidence'):
                verify_report(directory, 'report.json')

    def test_image_rejects_failed_or_changed_checkpoint(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            directory = Path(name); disk = directory / 'disk.qcow2'; disk.write_bytes(b'failed image')
            (directory / 'checkpoint.json').write_text(json.dumps({'stage': 'normal_shutdown_frozen', 'disk_sha256': '0' * 64}))
            disk.chmod(0o444)
            with self.assertRaisesRegex(ValueError, 'accepted frozen checkpoint'):
                verify_run(directory)

    def test_incomplete_probe_does_not_inherit_success(self):
        records, ok = group('REGSVC_PROBE_STARTED\n{"regsvc_case":"regsvc_probe_complete","status":"pass"}\nREGSVC_PROBE_EXIT=0\nREGSVC_PROBE_STARTED\n',
                            'REGSVC_PROBE_STARTED', 'REGSVC_PROBE_EXIT=')
        self.assertFalse(ok)
        self.assertEqual(records, [])

    def test_userenv_contract_is_reproducible_and_preserves_native_sections(self):
        native = ROOT / '.work/milestone-3-20261023/candidates-03-extracted/nt/ds/security/gina/userenv/main/obj/i386/userenv.dll'
        reference = ROOT / '.work/milestone-3-20261023/userenv-installed-inputs/WINDOWS/system32/userenv.dll'
        if not native.is_file() or not reference.is_file():
            self.skipTest('private UserEnv inputs unavailable')
        old = PE(native)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            directory = Path(name)
            first, second = directory / 'first.dll', directory / 'second.dll'
            prepare(native, reference, first)
            prepare(native, reference, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            new = PE(first)
            self.assertEqual(exports(new)[0], exports(PE(reference))[0])
            self.assertEqual(set(exports(new)[1]), set(range(100, 210)))
            for _, _, offset, size in old.sections:
                self.assertEqual(old.data[offset:offset + size], new.data[offset:offset + size])
            self.assertEqual(new.exports()['#200'], 'ue51sp3.#200')
            self.assertEqual(new.exports()['#201'], 'ue51sp3.#201')
            self.assertEqual(new.exports()['CheckXForestLogon'], 'ue51sp3.CheckXForestLogon')

    def test_every_userenv_binding_matches_the_sp3_public_symbols(self):
        import re
        from pdb_publics import public_symbols
        native = ROOT / '.work/native-shell-userenv-20261024/userenv-rebuild-01-extracted/nt/ds/security/gina/userenv/main/obj/i386/userenv.dll'
        reference = ROOT / '.work/milestone-3-20261023/userenv-installed-inputs/WINDOWS/system32/userenv.dll'
        pdb = ROOT / '.work/native-shell-userenv-20261024/symbols/userenv-sp3.pdb'
        if not all(p.is_file() for p in (native, reference, pdb)):
            self.skipTest('private native/SP3 symbol inputs unavailable')
        symbols = public_symbols(pdb, reference); by = {}
        for row in symbols:
            match = re.match(r'^_(\w+)@\d+$|^\?(\w+)@@', row['name'])
            if match:
                by.setdefault(row['rva'], set()).add(match[1] or match[2])
        source_def = (ROOT / 'Source/XPSP1/NT/ds/security/gina/userenv/main/userenv.def').read_text()
        source_private = {name:int(ordinal) for name,ordinal in re.findall(r'^\s+(\w+)\s+@(\d+)\s+NONAME', source_def, re.M)}
        native_names, native_rvas = exports(PE(native)); source = {**source_private, **native_names}
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            output = Path(name) / 'userenv.dll'; prepare(native, reference, output)
            actual = exports(PE(output))[1]
            for ordinal, rva in exports(PE(reference))[1].items():
                implementations = by[rva] & source.keys()
                if implementations:
                    self.assertEqual(len(implementations), 1)
                    function = next(iter(implementations))
                    self.assertEqual(actual[ordinal], native_rvas[source[function]], function)
                else:
                    self.assertIn(ordinal, (159, 200, 201))
                    self.assertTrue(PE(output).exports()['#'+str(ordinal)].startswith('ue51sp3.'))

    def test_mismatched_public_pdb_is_rejected(self):
        from pdb_publics import public_symbols
        reference = ROOT / '.work/milestone-3-20261023/userenv-installed-inputs/WINDOWS/system32/userenv.dll'
        wrong = ROOT / '.work/native-shell-userenv-20261024/symbols/winlogon-sp3.pdb'
        if not reference.is_file() or not wrong.is_file():
            self.skipTest('private symbol inputs unavailable')
        with self.assertRaisesRegex(ValueError, 'GUID/age does not match'):
            public_symbols(wrong, reference)

    def test_modified_native_input_is_rejected(self):
        native = ROOT / '.work/milestone-3-20261023/candidates-03-extracted/nt/ds/security/gina/userenv/main/obj/i386/userenv.dll'
        reference = ROOT / '.work/milestone-3-20261023/userenv-installed-inputs/WINDOWS/system32/userenv.dll'
        if not native.is_file() or not reference.is_file():
            self.skipTest('private UserEnv inputs unavailable')
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            directory = Path(name);changed = directory / 'bad.dll'
            data = bytearray(native.read_bytes());data[-1] ^= 1;changed.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'checksum invalid'):
                prepare(changed, reference, directory / 'output.dll')
            self.assertFalse((directory / 'output.dll').exists())


if __name__ == '__main__':
    unittest.main()
