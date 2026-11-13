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
                text = fixtures.suite(role, mode) + ''.join(fixtures.extra_files(role, mode).values())
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
        # The scan is asked for by the guest while it broadcasts NetBIOS name queries (the firewall's
        # broadcast-response window must be open while the observer probes), and the suite goes on
        # only when the observer has finished: no fixed waiting window.
        for role, label in (('audit', 'before'), ('harden', 'hardened'), ('proof', 'proof'), ('rollback', 'rolled-back')):
            text = fixtures.suite(role, 'up')
            on, request = text.index('echo on > %W%\\broadcast.on'), text.index('XP25_HOST_REQUEST=scan:' + label)
            wait, off = text.index('security_probe.exe hostwait ' + label), text.index('del %W%\\broadcast.on')
            self.assertLess(on, request)
            self.assertLess(request, wait)
            self.assertLess(wait, off)
            self.assertIn('ping -n 1 -w 200 xp25-nbprobe-%%N', text[on:request])
            self.assertNotIn('XP25_SEC_SCAN_WINDOW', text)

    def test_firewall_role_orders_every_state_with_the_observer(self):
        import security_fixtures as fixtures
        text = fixtures.suite('firewall', 'mp')
        stages = ['blocked', 'permitted', 'removed', 'after-unprivileged', 'admin-disabled', 'admin-enabled', 'service-stopped',
                  'service-started', 'after-restart']
        positions = [text.index('XP25_HOST_REQUEST=ports:%s ' % stage) for stage in stages]
        self.assertEqual(positions, sorted(positions))
        for stage in stages:                                       # each observation is awaited before the next guest step
            self.assertIn('security_probe.exe hostwait %s 600' % stage, text)
        # The listener is up before the first observation; the exception is added and removed by the administrator.
        self.assertLess(text.index('security_probe.exe listen %d' % fixtures.LISTENER_PORT), positions[0])
        self.assertLess(positions[0], text.index('netsh firewall add portopening protocol=TCP port=%d' % fixtures.LISTENER_PORT))
        self.assertLess(text.index('netsh firewall delete portopening protocol=UDP'), positions[2])
        # What the firewall still holds for the earlier datagram peer is measured right after the removal.
        self.assertLess(positions[2], text.index('XP25_HOST_REQUEST=udp-expiry:removed-expiry'))
        self.assertLess(text.index('XP25_HOST_REQUEST=udp-expiry:removed-expiry'), text.index('security_probe.exe admin'))
        # The unprivileged attempts run between "removed" and "after-unprivileged".
        self.assertLess(positions[2], text.index('security_probe.exe admin'))
        self.assertLess(text.index('security_probe.exe admin'), positions[3])
        # The restart is watched from before the guest goes down until it is back and checked.
        start, restart = text.index('XP25_HOST_REQUEST=watch-start:restart'), text.index('security_probe.exe power restart')
        self.assertLess(start, restart)
        self.assertLess(restart, positions[8])
        self.assertLess(positions[8], text.index('XP25_HOST_REQUEST=watch-stop:restart'))
        # Whatever the administrator turned off is on again before the baseline is verified.
        self.assertLess(text.index('net start SharedAccess'), text.index('XP25_FW_VERIFY_BOOT1'))
        self.assertEqual(text.count('fwcheck'), 3)

    def test_repeated_ai_rounds_start_from_a_clean_state(self):
        import security_fixtures as fixtures
        text = fixtures.suite('ai-repeat', 'mp', repeat=3)
        self.assertEqual(text.count('ai_probe.exe suite'), 3)
        self.assertEqual(text.count('ai_probe.exe provider'), 3)
        starts = [i for i in range(len(text)) if text.startswith('ai_probe.exe suite', i)]
        for n, start in enumerate(starts, 1):
            # ClippyAI and RoverAI are ended and the fixtures removed before every round.
            before = text[:start]
            self.assertGreater(before.rindex('security_probe.exe aireset'), before.rindex('XP25_AI_ROUND_STARTED=%d' % n))
            self.assertGreater(before.rindex('XP25AI-Fixtures'), before.rindex('security_probe.exe aireset'))
        self.assertLess(text.index('xp25sec-gateway-secret.cmd'), starts[0])

    def test_standard_user_role_plans_three_sessions(self):
        import security_fixtures as fixtures
        self.assertEqual(fixtures.LOGONS['standard-user'], ('admin', 'standard', 'standard'))
        admin = fixtures.suite('standard-user', 'up')
        startup = fixtures.extra_files('standard-user', 'tcg')['std-startup.cmd']
        # The account is a member of Users only; its password comes from the run, never from the fixture.
        self.assertIn('net user %XP25_STD_USER% %XP25_STD_PASSWORD% /add', admin)
        self.assertNotIn('localgroup Administrators %XP25_STD_USER%', admin)
        # MSGINA is told which account to offer before the administrator logs off.
        self.assertLess(admin.index('/v DefaultUserName /d %XP25_STD_USER%'), admin.index('power restart'))
        self.assertLess(admin.index('XP25Standard.cmd'), admin.index('power restart'))
        self.assertNotIn('power logoff', admin)
        # Every session but the standard user's does nothing; the first runs the desktop, the programs,
        # then restarts; the second repeats the desktop checks and powers off.
        self.assertLess(startup.index('if /i not "%USERNAME%"=="xp25user" goto :eof'), startup.index('desktop'))
        first = startup[:startup.index(':second')]
        self.assertLess(first.index('desktop %W%\\std-desktop-1.jsonl --hardened slow'), first.index('apps %W%\\std-apps-1.jsonl slow'))
        self.assertLess(first.index('std-apps-1'), first.index('power restart'))
        second = startup[startup.index(':second'):]
        self.assertLess(second.index('std-desktop-2'), second.index('power shutdown'))
        self.assertEqual(fixtures.STD_USER, 'xp25user')

    def test_image_upgrade_keeps_the_original_install_record(self):
        import security_fixtures as fixtures
        upgrade, install = fixtures.suite('image-upgrade', 'up'), fixtures.suite('image-install', 'up')
        self.assertIn('upgrade-81-apply.jsonl', upgrade)
        self.assertNotIn('install-apply.jsonl', upgrade)
        self.assertIn('install-apply.jsonl', install)
        self.assertLess(upgrade.index('XP25_SEC_VERIFY_BEFORE_UPGRADE_EXIT'), upgrade.index('copy /y "%U%\\xp25sec-XP25Sec.exe"'))
        self.assertLess(upgrade.index('rmdir /s /q C:\\xp25sec'), upgrade.index('XP25_SEC_SUITE_DONE'))

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


class ObserverTests(unittest.TestCase):
    def test_guest_requests_are_parsed_strictly(self):
        import re
        import security_network as network
        import inspect
        source = inspect.getsource(network.scanner)
        pattern = re.compile(re.search(r"re\.compile\(r'(.+?)', re\.M\)", source).group(1), re.M)
        text = ('XP25_HOST_REQUEST=ports:blocked \nnoise XP25_HOST_REQUEST=scan:x\nXP25_HOST_REQUEST=scan:proof\n'
                'XP25_HOST_REQUEST=watch-start:restart\nXP25_HOST_REQUEST=ports:../../etc\nXP25_HOST_REQUEST=PORTS:a\n'
                'XP25_HOST_REQUEST=ports:' + 'a' * 41 + '\n')
        self.assertEqual(pattern.findall(text), [('ports', 'blocked'), ('scan', 'proof'), ('watch-start', 'restart')])

    def test_capture_is_segmented_by_marker_frames(self):
        import struct
        import security_pcap as pcap
        import security_network as network
        guest, host = bytes([10, 25, 0, 10]), bytes([10, 25, 0, 1])
        gmac, hmac = bytes.fromhex('525400250002'), bytes.fromhex('525400250001')

        def ip(source, target, protocol, payload):
            header = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64, protocol, 0, source, target)
            return (hmac if target == host else gmac) + (gmac if source == guest else hmac) + b'\x08\x00' + header + payload

        def tcp(source, target, sport, dport, flags):
            return ip(source, target, 6, struct.pack('>HHIIBBHHH', sport, dport, 0, 0, 0x50, flags, 0, 0, 0))

        def udp(source, target, sport, dport):
            return ip(source, target, 17, struct.pack('>HHHH', sport, dport, 8, 0))

        def marker(text):
            return network.MARK_DESTINATION + hmac + network.MARK_ETHERTYPE + ('XP25-MARK:' + text).encode().ljust(46, b'\0')
        frames = [tcp(host, guest, 40000, 135, 0x02),                                   # before any marker: whole capture only
                  marker('blocked:start'), tcp(host, guest, 40001, 5025, 0x02), udp(host, guest, 40002, 137),
                  udp(guest, bytes([10, 25, 0, 255]), 137, 137), marker('blocked:end'),
                  marker('permitted:start'), tcp(host, guest, 40003, 5025, 0x02), tcp(guest, host, 5025, 40003, 0x12),
                  udp(guest, host, 5025, 40004), tcp(host, guest, 40005, 139, 0x02), tcp(guest, host, 139, 40005, 0x14),
                  # The guest's own outbound connection and its reset are not answers to the observer.
                  tcp(guest, host, 1030, 8081, 0x02), tcp(guest, host, 1030, 8081, 0x14),
                  udp(bytes(4), b'\xff\xff\xff\xff', 68, 67), marker('permitted:end')]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'network.pcap'
            with path.open('wb') as f:
                f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1))
                for n, frame in enumerate(frames):
                    f.write(struct.pack('<IIII', n, 0, len(frame), len(frame)) + frame)
            result = pcap.summarize(path)
        blocked, permitted = result['segments']['blocked'], result['segments']['permitted']
        self.assertEqual(list(result['segments']), ['blocked', 'permitted'])
        self.assertEqual(blocked['tcp_syn_to_guest'], {'5025': 1})
        self.assertEqual(blocked['tcp_synack_from_guest'], {})
        self.assertEqual(blocked['udp_to_guest'], {'137': 1})
        self.assertEqual(blocked['guest_broadcast_udp'], {'137': 1})
        self.assertEqual(blocked['udp_replies_from_guest'], {})
        self.assertEqual(permitted['tcp_synack_from_guest'], {'5025': 1})
        self.assertEqual(permitted['udp_replies_from_guest'], {})          # no datagram was sent to 5025 in this segment
        self.assertEqual(permitted['guest_udp_unicast_out'], {'40004': 1})
        self.assertEqual(permitted['tcp_rst_from_guest'], {'139': 1})
        self.assertEqual(permitted['guest_tcp_connections_out'], 1)
        self.assertEqual(permitted['dhcp_requests_without_address'], 1)
        self.assertEqual(blocked['dhcp_requests_without_address'], 0)
        self.assertEqual(result['whole_capture']['tcp_syn_to_guest'], {'135': 1, '139': 1, '5025': 2})
        self.assertTrue(blocked['closed'] and permitted['closed'])

    def test_kernel_check_reads_export_and_import_tables(self):
        if not (TOOLCHAIN / 'i686-w64-mingw32-gcc-posix').is_file():
            self.skipTest('private MinGW toolchain unavailable')
        import security_kernel_check as check
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'k.c'
            source.write_text('__declspec(dllexport) int KeOne(void) { return 1; }\n__declspec(dllexport) int KeTwo(void) { return 2; }\n'
                              'int __stdcall DllMain(void *a, unsigned b, void *c) { (void)a; (void)b; (void)c; return 1; }\n')
            user = Path(d) / 'u.c'
            user.write_text('__declspec(dllimport) int KeOne(void);\nint __stdcall DllMain(void *a, unsigned b, void *c) { (void)a; (void)b; (void)c; return KeOne(); }\n')
            cc = str(TOOLCHAIN / 'i686-w64-mingw32-gcc-posix')
            subprocess.run([cc, '-shared', '-nostdlib', '-Wl,--entry,_DllMain@12', '-o', str(Path(d) / 'ntoskrnl.exe'), str(source),
                            '-Wl,--out-implib,' + str(Path(d) / 'libk.a')], check=True, capture_output=True)
            subprocess.run([cc, '-shared', '-nostdlib', '-Wl,--entry,_DllMain@12', '-o', str(Path(d) / 'drv.sys'), str(user),
                            '-L', d, '-lk'], check=True, capture_output=True)
            exports = check.PE((Path(d) / 'ntoskrnl.exe').read_bytes()).exports()
            imports = check.PE((Path(d) / 'drv.sys').read_bytes()).imports()
        self.assertEqual(sorted(exports), ['KeOne', 'KeTwo'])
        self.assertIsNone(exports['KeOne'][2])
        self.assertEqual(imports, {'ntoskrnl.exe': ['KeOne']})


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
