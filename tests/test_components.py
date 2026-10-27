"""Fail closed on changed component evidence and modified native PE artifacts."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
from inspect_component import PE


class ComponentEvidenceTests(unittest.TestCase):
    def test_runtime_checker_rejects_reference_tree_output(self):
        result = subprocess.run([sys.executable, str(ROOT / 'vm/component_results.py'),
                                 str(ROOT / 'Source/XPSP1/NT'), '--expected-scm',
                                 str(ROOT / '.work/nonexistent-services.exe')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('runtime evidence must remain under private .work/', result.stderr)

    def test_manifest_rejects_a_previously_passing_but_changed_record(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            directory = Path(name)
            serial = directory / 'serial.log'
            serial.write_text('original passing observations')
            digest = hashlib.sha256(serial.read_bytes()).hexdigest()
            (directory / 'component-results.json').write_text(json.dumps({
                'passed': True, 'evidence_sha256': {'serial.log': digest}}))
            (directory / 'inventory.json').write_text('{}')
            serial.write_text('later incomplete or failing observations')
            output = directory / 'manifest.json'
            result = subprocess.run([sys.executable, str(ROOT / 'build/record_component_manifest.py'),
                '--source-inventory', str(directory / 'inventory.json'), '--output', str(output),
                '--component', 'services', 'base/screg/sc/server', str(directory / 'unused.exe'),
                '--runtime', str(directory)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('runtime evidence changed after validation', result.stderr)
            self.assertFalse(output.exists())

    def test_modified_native_binary_fails_checksum_inspection(self):
        native = ROOT / '.work/milestone-3-20261023/scm-build-02-extracted/nt/base/screg/sc/server/obj/i386/services.exe'
        if not native.is_file():
            self.skipTest('private native SCM build is unavailable')
        self.assertTrue(PE(native).inspect()['checksum_valid'])
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            modified = Path(name) / 'services.exe'
            data = bytearray(native.read_bytes())
            data[-1] ^= 1
            modified.write_bytes(data)
            self.assertFalse(PE(modified).inspect()['checksum_valid'])


if __name__ == '__main__':
    unittest.main()
