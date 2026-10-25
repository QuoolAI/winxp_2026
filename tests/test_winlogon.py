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
        self.assertIn('cases=24', self.compile_and_run('winlogon_environment', 'environment.c'))


class SessionEngineTests(unittest.TestCase):
    def compiler(self):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler unavailable')
        return compiler

    def test_real_coordinator_with_explicit_drivers_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            binary = Path(directory) / 'session-tests'
            command = [self.compiler(), '-std=c89', '-pedantic', '-Wall', '-Wextra',
                       '-Werror', '-DXP25_SESSION_TEST=1', '-I',
                       str(ROOT / 'components/winlogon'), str(ROOT / 'tests/winlogon_session.c')]
            command += [str(ROOT / 'components/winlogon' / name)
                        for name in ('session_engine.c', 'policy.c', 'state.c')]
            subprocess.run(command + ['-o', str(binary)], check=True, capture_output=True)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('XP25_SESSION_TEST_ONLY cases=', run.stdout)
            self.assertIn('failures=0', run.stdout)

    def test_production_compilation_rejects_test_driver_mode(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            run = subprocess.run([self.compiler(), '-std=c89',
                '-DXP25_PRODUCTION_WINLOGON=1', '-DXP25_SESSION_TEST=1',
                '-I', str(ROOT / 'components/winlogon'), '-c',
                str(ROOT / 'components/winlogon/session_engine.c'), '-o',
                str(Path(directory) / 'forbidden.o')], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('Test session drivers cannot be compiled into production Winlogon', run.stderr)
            self.assertFalse((Path(directory) / 'forbidden.o').exists())


if __name__ == '__main__':
    unittest.main()
