"""Check the account-switch paint oracle (vm/winlogon_switch_probe.py) without a guest.

Synthetic 640x480 frames stand in for QMP screendumps; these tests establish only that
the oracle tells a painted logon dialog from a blank one and from the black gap between
dialogs, reads the logged-on account SIDs from Winlogon serial records, and refuses
inconsistent two-account options. They do not establish anything about a guest.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'vm/winlogon_switch_probe.py'


def load_probe():
    spec = importlib.util.spec_from_file_location('winlogon_switch_probe', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frame(path, regions):
    """A black 640x480 P6 frame with the given (box, colour) rectangles filled."""
    pixels = bytearray(640 * 480 * 3)
    for box, colour in regions:
        for y in range(box['y0'], box['y1']):
            for x in range(box['x0'], box['x1']):
                pixels[(y * 640 + x) * 3:(y * 640 + x) * 3 + 3] = bytes(colour)
    path.write_bytes(b'P6\n# synthetic\n640 480\n255\n' + bytes(pixels))
    return path


class SwitchProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe()

    def test_painted_blank_and_absent_dialogs(self):
        probe = self.probe
        white = (255, 255, 255)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            directory = Path(directory)
            painted = frame(directory / 'painted.ppm', [(probe.BODY, probe.BEIGE), (probe.FIELD, white),
                                                        (probe.PASSWORD_FIELD, white)])
            blank = frame(directory / 'blank.ppm', [(probe.BODY, probe.BEIGE)])
            gap = frame(directory / 'gap.ppm', [])
            self.assertTrue(probe.dialog_present(painted))
            self.assertEqual(probe.painted_fraction(painted), 1.0)
            self.assertEqual(probe.painted_fraction(painted, probe.PASSWORD_FIELD), 1.0)
            self.assertTrue(probe.dialog_present(blank))
            self.assertEqual(probe.painted_fraction(blank), 0.0)
            self.assertEqual(probe.painted_fraction(blank, probe.PASSWORD_FIELD), 0.0)
            self.assertFalse(probe.dialog_present(gap))

    def test_logon_sids_come_from_winlogon_records_only(self):
        rows = [{'xp25_winlogon': 'profile_loaded', 'status': 0},
                {'xp25_winlogon': 'S-1-5-21-1-2-3-1003', 'status': 0},
                {'other': 'S-1-5-21-9-9-9-500'},
                {'xp25_winlogon': 'S-1-5-21-1-2-3-1005', 'status': 0}]
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            serial = Path(directory) / 'serial.log'
            serial.write_text('noise\r\n' + ''.join(json.dumps(r) + '\r\n' for r in rows) + '{"xp25_winlogon":"S-1-5-21-')
            self.assertEqual(self.probe.logon_sids(serial), ['S-1-5-21-1-2-3-1003', 'S-1-5-21-1-2-3-1005'])
            self.assertEqual(self.probe.logon_sids(Path(directory) / 'missing.log'), [])

    def test_inconsistent_two_account_options_are_refused(self):
        base = [sys.executable, str(SCRIPT), '--name', 'x', '--image', '/dev/null', '--image-sha256', '0',
                '--probe', '/dev/null']
        for extra in (['--second-user', 'XP25B'],
                      ['--second-user', 'XP25', '--second-password', 'sw1tch25'],
                      ['--second-user', 'XP25B', '--second-password', 'Upper1'],
                      ['--second-user', 'XP25B', '--second-password', 'sw1tch25', '--cycles', '6',
                       '--wrong-password-cycle', '2'],
                      ['--wrong-password-cycle', '1'],
                      ['--stage', '/WINDOWS/xp25krnl.exe=kernel.exe'],
                      ['--stage', '/WINDOWS/system32/xp25hal.dll']):
            result = subprocess.run(base + extra, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, extra)
            self.assertIn('error:', result.stderr)

    def test_switch_script_alternates_and_creates_the_account_once(self):
        script = self.probe.SWITCH_CMD.replace('{user}', 'XP25B').replace('{password}', 'sw1tch25')
        self.assertIn('set NEXT=XP25B\r\nif /i "%USERNAME%"=="XP25B" set NEXT=XP25\r\n', script)
        self.assertIn('if exist C:\\xp25\\switch-account.created goto offer', script)
        self.assertIn('/v DefaultUserName /d %NEXT% /f', script)
        self.assertTrue(script.endswith('winlogon-switch-probe.exe power logoff\r\n'))


if __name__ == '__main__':
    unittest.main()
