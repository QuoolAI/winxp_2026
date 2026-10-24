"""Exercise the original Winlogon transition core and synthetic key decoder.

These portable tests do not establish native authentication or desktop safety.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WinlogonCoreTests(unittest.TestCase):
    def compile_and_run(self, name, implementation):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler unavailable')
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            binary = Path(directory) / name
            subprocess.run([compiler, '-std=c89', '-pedantic', '-Wall', '-Wextra',
                            '-Werror', '-I', str(ROOT / 'components/winlogon'),
                            str(ROOT / 'tests' / (name + '.c')),
                            str(ROOT / 'components/winlogon' / implementation),
                            '-o', str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], check=True, capture_output=True,
                                    text=True, timeout=30)
            self.assertIn('failures=0', result.stdout)
            return result.stdout

    def test_authentication_and_resource_transition_guards(self):
        self.assertIn('checks=320991', self.compile_and_run('winlogon_state', 'state.c'))

    def test_stored_key_decoder_rejects_malformed_synthetic_input(self):
        self.assertIn('cases=7', self.compile_and_run('winlogon_bootkey', 'bootkey_codec.c'))

    def test_environment_bounds_duplicates_and_unicode_values(self):
        self.assertIn('cases=13', self.compile_and_run('winlogon_environment', 'environment.c'))


if __name__ == '__main__':
    unittest.main()
