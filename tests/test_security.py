"""Host checks for the XP25 security baseline and audit components.

They exercise the portable core, the lab fixtures, the namespace scanner and
the build contracts. They do not establish behavior on Windows XP; that
evidence comes from recorded guest runs (docs/security-regression.md).
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / 'components/security'
STRICT = ['-std=c89', '-pedantic', '-Wall', '-Wextra', '-Werror', '-Wno-overlength-strings']
TOOLCHAIN = Path(os.environ.get('XP25_MINGW', ROOT / '.work/toolchains/mingw-binutils/usr/bin'))
MODULES = ROOT / '.work/security-20261111/guest-modules-01/WINDOWS/system32'
sys.path.insert(0, str(ROOT / 'vm'))
sys.path.insert(0, str(ROOT / 'build'))


class PortableCoreTests(unittest.TestCase):
    def test_tables_backup_codec_and_rules(self):
        cc = shutil.which('cc')
        if not cc:
            self.skipTest('host C compiler unavailable')
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            binary = Path(d) / 'security_core'
            sanitize = ['-fsanitize=address,undefined'] if sys.platform.startswith('linux') else []
            subprocess.run([cc] + STRICT + sanitize + ['-g', '-I', str(S / 'core'), str(ROOT / 'tests/security_core.c'),
                                                      str(S / 'core/sec_core.c'), '-o', str(binary)], check=True, capture_output=True)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('XP25_SECURITY_CORE failures=0', run.stdout)

    def test_core_has_no_windows_or_runtime_dependency(self):
        text = (S / 'core/sec_core.c').read_text() + (S / 'core/sec_core.h').read_text()
        for forbidden in ('<windows.h>', '<string.h>', '<stdio.h>', '<stdlib.h>', 'malloc('):
            self.assertNotIn(forbidden, text)

    def test_tools_take_no_target_from_the_command_line(self):
        # The baseline utility applies its reviewed tables only; the audit never opens anything for writing
        # except its own snapshot in the protected store.
        utility = (S / 'xp25sec/main.c').read_text()
        self.assertNotIn('argv', utility[:utility.index('void __cdecl XP25SecMain')])
        audit = (S / 'xp25audit/main.c').read_text()
        for call in ('TerminateProcess', 'DeleteFileW', 'RegSetValueEx', 'RegDeleteKey', 'ChangeServiceConfig', 'ControlService',
                     'StartService', 'SetNamedSecurityInfo', 'AdjustTokenGroups', 'WriteProcessMemory', 'socket(', 'connect('):
            self.assertNotIn(call, audit, call)
        self.assertEqual(audit.count('GENERIC_WRITE'), 1)       # the snapshot file in the protected store


class FixtureTests(unittest.TestCase):
    def test_roles_are_self_contained_and_avoid_managed_directories(self):
        import security_fixtures as fixtures
        for role in fixtures.ROLES:
            for mode in ('up', 'mp', 'tcg'):
                text = fixtures.suite(role, mode)
                self.assertNotIn('\n', text.replace('\r\n', ''), role)
                self.assertIn('XP25_SEC_SUITE_DONE', text)
                # shutdown.exe needs the InitShutdown interface the XP25 Winlogon does not serve.
                self.assertNotIn('shutdown.exe', text.lower())
                # Payload is staged in the profile, never in a directory the baseline protects.
                self.assertNotIn('C:\\xp25\\sec', text)
                self.assertNotIn('C:\\Program Files\\XP25\\Security\\security_probe', text)
        self.assertIn('slow', fixtures.suite('harden', 'tcg'))
        self.assertNotIn(' slow', fixtures.suite('harden', 'up'))

    def test_hardened_roles_verify_before_and_after_the_workload(self):
        import security_fixtures as fixtures
        for role in ('harden', 'proof'):
            text = fixtures.suite(role, 'up')
            first = text.index('XP25_SEC_VERIFY_EXIT')
            self.assertLess(first, text.index('security_probe.exe admin'))
            self.assertLess(text.index('XP25_AI_PROBE_EXIT'), text.index('XP25_SEC_FINAL_VERIFY_EXIT'))
            self.assertIn('--hardened', text)
            # Remote Registry: refused while disabled, then proven after an administrator re-enables it, then disabled again.
            self.assertLess(text.index('REGSVC_PROBE_WHILE_DISABLED_EXIT'), text.rindex('sc config RemoteRegistry start= demand'))
            self.assertLess(text.index('REGSVC_PROBE_EXIT='), text.index('XP25_SEC_REAPPLY_EXIT'))
        self.assertNotIn('--hardened', fixtures.suite('audit', 'up'))
        # The scan window is a period of NetBIOS broadcasts, not an idle wait: the firewall's
        # broadcast-response window must be open while the namespace scanner probes.
        for role in ('audit', 'harden', 'proof', 'rollback'):
            text = fixtures.suite(role, 'up')
            window = text[text.index('XP25_SEC_SCAN_WINDOW_OPEN'):text.index('XP25_SEC_SCAN_WINDOW_CLOSED')]
            self.assertIn('ping -n 1 -w 200 xp25-nbprobe-%%N', window)

    def test_image_install_leaves_no_test_payload(self):
        import security_fixtures as fixtures
        text = fixtures.suite('image-install', 'up')
        for needle in ('xp25sec-security_probe.exe"', 'rmdir /s /q C:\\xp25sec', 'del "%U%\\xp25sec-suite.cmd"', 'XP25Audit.exe" snapshot'):
            self.assertIn(needle, text)
        self.assertNotIn('ai_probe', text)
        self.assertNotIn('security_probe.exe admin', text)
        self.assertLess(text.index('rmdir /s /q'), text.index('XP25_SEC_SUITE_DONE'))


class ScannerTests(unittest.TestCase):
    def test_tcp_states_distinguish_open_from_closed(self):
        import security_network as network
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        free_port = closed.getsockname()[1]
        closed.close()
        original = network.GUEST
        network.GUEST = '127.0.0.1'
        try:
            self.assertEqual(network.tcp(listener.getsockname()[1]), (listener.getsockname()[1], 'open'))
            self.assertEqual(network.tcp(free_port), (free_port, 'closed'))
        finally:
            network.GUEST = original
            listener.close()
        self.assertIn(135, network.TCP_PORTS)
        self.assertIn(445, network.TCP_PORTS)
        self.assertIn(3389, network.TCP_PORTS)
        self.assertEqual(set(network.UDP_PROBES), {123, 137, 138, 161, 445, 500, 1900, 4500})

    def test_name_service_burst_counts_answers(self):
        import security_network as network
        import threading
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0))
        server.settimeout(5)

        def answer_first_three():
            for _ in range(3):
                data, peer = server.recvfrom(2048)
                server.sendto(b'reply', peer)
        thread = threading.Thread(target=answer_first_three, daemon=True)
        thread.start()
        original_guest, original_connect = network.GUEST, socket.socket.connect
        port = server.getsockname()[1]
        network.GUEST = '127.0.0.1'
        socket.socket.connect = lambda self, address: original_connect(self, (address[0], port) if address[1] == 137 else address)
        try:
            result = network.nbns_burst(probes=6, interval=0.2)
        finally:
            network.GUEST, socket.socket.connect = original_guest, original_connect
            thread.join(timeout=5)
            server.close()
        self.assertEqual(result['probes'], 6)
        self.assertEqual(result['answers'], 3)


class OfflineInventoryTests(unittest.TestCase):
    def test_origin_classification(self):
        import security_offline_audit as audit
        self.assertEqual(audit.origin({'file_version': '5.1.2600.1106', 'private_build': True}), 'xp25_source_built_sp1_qfe1106')
        self.assertEqual(audit.origin({'file_version': '5.1.2600.1106', 'private_build': False}), 'sp1')
        self.assertEqual(audit.origin({'file_version': '5.1.2600.5512'}), 'sp3')
        self.assertEqual(audit.origin({'file_version': '6.0.2900.6242'}), 'other')
        self.assertEqual(audit.origin({'file_version': '6.0.2600.0'}), 'rtm')
        self.assertEqual(audit.origin({}), 'other')
        self.assertIsNone(audit.pe_facts(b'not a PE image' * 40))


class BuildContractTests(unittest.TestCase):
    def test_kernel_export_patch_adds_only_an_implemented_routine(self):
        if not shutil.which('xorriso'):
            self.skipTest('xorriso unavailable')
        import prepare_kernel_exports as exports
        source = exports.SOURCE.read_text('latin1')
        for name, implementation in exports.IMPLEMENTATIONS.items():
            self.assertNotIn('    ' + name + '\n', source)             # not exported by the reference tree
            self.assertIn(name, (ROOT / 'Source/XPSP1/NT' / implementation).read_text('latin1'))
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            out = Path(d) / 'media'
            subprocess.run([sys.executable, str(ROOT / 'build/prepare_kernel_exports.py'), '--output', str(out)], check=True, capture_output=True)
            original = (out / 'media/original/ntoskrnl.src').read_bytes()
            patched = (out / 'media/patched/ntoskrnl.src').read_bytes()
            self.assertEqual(original, exports.SOURCE.read_bytes())
            added = [line for line in patched.splitlines() if line not in original.splitlines()]
            self.assertEqual(added, [b'    KeFlushQueuedDpcs'])
            self.assertEqual(len(patched.splitlines()), len(original.splitlines()) + 1)
            self.assertEqual(json.loads((out / 'manifest.json').read_text())['added_exports'], ['KeFlushQueuedDpcs'])

    def test_cross_build_passes_guest_import_contract(self):
        if not (TOOLCHAIN / 'i686-w64-mingw32-gcc-posix').is_file() or not MODULES.is_dir():
            self.skipTest('private MinGW toolchain or extracted guest modules unavailable')
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            out = Path(d) / 'build'
            run = subprocess.run([sys.executable, str(ROOT / 'build/security_build.py'), '--toolchain', str(TOOLCHAIN),
                                  '--guest-modules', str(MODULES), '--output', str(out)], capture_output=True, text=True, timeout=600)
            self.assertEqual(run.returncode, 0, run.stdout[-2000:] + run.stderr[-2000:])
            result = json.loads((out / 'result.json').read_text())
            self.assertEqual(result['status'], 'compiled_static_checks_passed')
            self.assertEqual(set(result['targets']), {'XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe'})
            # The audit needs no networking library: it reads the system's own tables.
            self.assertNotIn('ws2_32.dll', result['targets']['XP25Audit.exe']['imports'])
            self.assertNotIn('wininet.dll', result['targets']['XP25Audit.exe']['imports'])

    def test_native_sources_list_local_files_only(self):
        for name in ('xp25sec', 'xp25audit'):
            text = (S / name / 'sources').read_text()
            self.assertIn('MSC_WARNING_LEVEL=/W4 /WX', text)
            sources = [line for line in text.splitlines() if line.startswith('SOURCES=')][0]
            self.assertNotIn('..', sources)                           # build.exe compiles only sources in the directory
            for wrapper in ('core.c', 'win.c'):
                self.assertIn('#include "../', (S / name / wrapper).read_text())


if __name__ == '__main__':
    unittest.main()
