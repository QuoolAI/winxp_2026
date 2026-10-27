"""Host gates for the XP25 Supermium compatibility proxy, reduced-privilege
launch registration and watch A/B tooling. Guest behaviour is verified only by
recorded runs under .work; these tests never execute browser code."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
from browser_ab_report import block
from browser_config import URL_ALLOWLIST, generate
from browser_diagnostic_media import watch_ab_suite, containment_suite, inherit_suite
from browser_tools import definition_exports, forwarder_modules, TARGETS
from prepare_browser import install_watch_proxy
from pwrp_proxy import DEF, ORIGINAL_SHA256, proxy_def

ORIGINAL = ROOT / '.work/browser-20261025/supermium-150/Supermium/pwrp_k32.dll'


class ProxyDefinitionTests(unittest.TestCase):
    def test_only_the_watch_api_is_reimplemented(self):
        rows = definition_exports(DEF)
        local = {name for name, (_, forwarder) in rows.items() if not forwarder}
        self.assertEqual(local, {'ReadDirectoryChangesW'})
        self.assertIn('Xp25ReadDirectoryChangesW', DEF.read_text())
        self.assertEqual(rows['LoadStringW'][1], 'user32.LoadStringW')
        self.assertEqual(rows['CreateIoCompletionPort'][1], 'pwrp_k32_sm.CreateIoCompletionPort')
        self.assertEqual(len({ordinal for ordinal, _ in rows.values()}), len(rows))
        self.assertIn(ORIGINAL_SHA256, DEF.read_text())

    def test_forward_targets_are_the_renamed_original_and_user32(self):
        modules = forwarder_modules(DEF)
        self.assertEqual(set(modules), {'pwrp_k32_sm', 'user32'})
        self.assertEqual(len(modules['pwrp_k32_sm']) + len(modules['user32']), len(definition_exports(DEF)) - 1)

    @unittest.skipUnless(ORIGINAL.exists(), 'private pinned Supermium wrapper not present')
    def test_committed_definition_matches_pinned_original(self):
        self.assertEqual(proxy_def(ORIGINAL).encode('ascii'), DEF.read_bytes())

    def test_unpinned_wrapper_is_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            fake = Path(d) / 'pwrp_k32.dll'
            fake.write_bytes(b'MZ not the pinned wrapper')
            with self.assertRaisesRegex(ValueError, 'pinned Supermium wrapper'):
                proxy_def(fake)
            media = Path(d) / 'media'
            (media / 'Supermium').mkdir(parents=True)
            (media / 'Supermium/pwrp_k32.dll').write_bytes(b'MZ different')
            with self.assertRaisesRegex(ValueError, 'pinned Supermium wrapper'):
                install_watch_proxy(media, fake)
            self.assertFalse((media / 'Supermium/pwrp_k32_sm.dll').exists())


class LaunchRegistrationTests(unittest.TestCase):
    def test_entry_points_use_launcher_and_internet_stays_blocked(self):
        pin = json.loads((ROOT / 'components/browser/release.json').read_text())
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            out = Path(d)
            generate(out, pin, True)
            registry = (out / 'associations.reg').read_text(encoding='utf-16')
            install = (out / 'install.cmd').read_text()
            scope = json.loads((out / 'registration-scope.json').read_text())
        self.assertIn('Supermium\\shell\\open\\command]\n@="\\"C:\\\\Program Files\\\\XP25Browser\\\\XP25Browser.exe\\""', registry)
        self.assertNotIn('Supermium\\\\chrome.exe\\" --', registry)
        self.assertIn('[-HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Supermium]', registry)
        self.assertIn('[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Supermium\\URLBlocklist]\n"1"="*"', registry)
        for i, value in enumerate(URL_ALLOWLIST):
            self.assertIn('"%d"="%s"' % (i + 1, value), registry)
        self.assertFalse(any(v.startswith(('http', '*')) for v in URL_ALLOWLIST))
        self.assertIn(['HKLM', 'Software\\Policies\\Supermium'], scope)
        self.assertIn('XP25Browser.exe', install)
        self.assertIn('"SoftwareRendering"=dword:00000001', registry)
        for forbidden in ['no-sandbox', 'ignore-certificate', 'disable-web-security']:
            self.assertNotIn(forbidden, registry)

    def test_launcher_source_fails_closed_without_reduced_token(self):
        source = (ROOT / 'components/browser/browserctl.c').read_text()
        self.assertIn('SAFER_LEVELID_NORMALUSER', source)
        self.assertNotIn('CreateProcessW(', source)
        self.assertIn('if(!token){error=GetLastError();number("reduced_token_error",error);return', source)


class WatchAbTests(unittest.TestCase):
    def test_blocks_alternate_and_verify_layout(self):
        suite = watch_ab_suite(5, 45)
        tags = [line.split()[-3] for line in suite.splitlines() if line.startswith('D:\\browser_debug.exe')]
        self.assertEqual(tags, ['dorig1', 'dprox1', 'dorig2', 'dprox2', 'porig1', 'pprox1', 'porig2', 'pprox2'])
        for tag in tags:
            self.assertIn('echo XP25_AB_LAYOUT_' + tag.upper() + '=%ERRORLEVEL% > COM1', suite)
        self.assertLess(suite.index('shutdown.exe'), suite.index('\n:orig\n'))
        with self.assertRaises(ValueError):
            watch_ab_suite(5, 5)

    def test_report_attributes_only_from_logged_module_ranges(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as d:
            log = Path(d) / 'dorig1-events.log'
            log.write_text('\n'.join([
                'MODULE cycle=1 pid=10 base=1a000000 size=0c000000 timestamp=0 checksum=0 path=C:\\x\\chrome.dll',
                'EXCEPTION cycle=1 pid=10 tid=2 code=80000003 address=217b96f8 first=1 flags=0 parameters=3 p0=0 p1=0',
                'EXCEPTION cycle=1 pid=11 tid=3 code=c0000005 address=217b96f8 first=1 flags=0 parameters=2 p0=0 p1=0',
                'PROCESS_EXIT cycle=1 pid=10 code=ffff7002 root=1',
                'CYCLE_EXIT cycle=1 root_code=ffff7002 elapsed_ms=1']) + '\n')
            rows = block(log)
        self.assertEqual(rows['exceptions'][0]['rva'], hex(0x77b96f8))
        self.assertIn('file_path_watcher_win.cc', rows['exceptions'][0]['identified'])
        self.assertIsNone(rows['exceptions'][1]['module'])
        self.assertEqual(rows['abnormal_exits'][0]['meaning'], 'crashpad_snapshot_failed')


class DiagnosticToolingTests(unittest.TestCase):
    def test_inherit_and_containment_suites_install_then_probe(self):
        inh = inherit_suite()
        self.assertIn('call D:\\install.cmd', inh)
        self.assertIn('D:\\browser_inherit.exe "C:\\Program Files\\Supermium"', inh)
        self.assertLess(inh.index('install.cmd'), inh.index('browser_inherit.exe'))
        con = containment_suite()
        self.assertIn('D:\\browser_sandbox.exe', con)
        self.assertIn('XP25Browser.exe', con)

    def test_inherit_and_watch_probes_are_registered_targets(self):
        for name in ('browser_inherit', 'browser_watch', 'browser_launch'):
            self.assertIn(name, TARGETS)

    def test_app_event_reader_parses_application_error_records(self):
        import struct
        from read_app_events import records
        # One synthetic EVENTLOGRECORD: source "Application Error", two strings.
        source = 'Application Error\x00'.encode('utf-16le')
        strings = 'chrome.exe\x00150.0.7871.255\x00'.encode('utf-16le')
        string_offset = 56 + len(source)
        length = string_offset + len(strings) + 4
        rec = bytearray(length)
        struct.pack_into('<I', rec, 0, length)
        rec[4:8] = b'LfLe'
        struct.pack_into('<I', rec, 8, 7)          # record number
        struct.pack_into('<I', rec, 20, 1000)      # event id
        struct.pack_into("<H", rec, 26, 2)          # NumStrings (offset 26)
        struct.pack_into('<I', rec, 36, string_offset)
        rec[56:56+len(source)] = source
        rec[string_offset:string_offset+len(strings)] = strings
        rows = list(records(bytes(rec)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['source'], 'Application Error')
        self.assertEqual(rows[0]['event_id'], 1000)
        self.assertIn('chrome.exe', rows[0]['strings'])

class ContainmentArchitectureTests(unittest.TestCase):
    def test_launcher_applies_restricted_token_and_job(self):
        src = (ROOT / 'components/browser/browserctl.c').read_text()
        # Restricted token via SAFER, launched suspended, placed in a job, then resumed.
        self.assertIn('SAFER_LEVELID_NORMALUSER', src)
        self.assertIn('CreateJobObjectW', src)
        self.assertIn('AssignProcessToJobObject', src)
        self.assertIn('CREATE_SUSPENDED', src)
        self.assertLess(src.index('AssignProcessToJobObject'), src.index('ResumeThread'))
        # No breakaway and no kill-on-close so the tree stays contained and survives the launcher.
        self.assertNotIn('JOB_OBJECT_LIMIT_BREAKAWAY_OK', src)
        self.assertNotIn('JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK', src)
        # Still fails closed without the restricted token.
        self.assertIn('if(!token){', src)
        self.assertNotIn('CreateProcessW(', src)

    def test_negative_probe_checks_privileged_boundaries(self):
        src = (ROOT / 'tests/guest/browser_sandbox.c').read_text()
        self.assertIn('PRIVBOUNDARY', src)
        self.assertIn('GetSystemDirectoryW', src)        # protected system-file write test
        self.assertIn('system_inject', src)              # SYSTEM-process injection test
        self.assertIn('services.exe', src)

    def test_sandbox_capability_analysis_states_renderer_sandbox_unavailable(self):
        import json
        a = ROOT / '.work/browser-fix-20261026/sandbox-analysis-01/nt51-sandbox-capability.json'
        if not a.exists():
            self.skipTest('private sandbox analysis not present')
        d = json.loads(a.read_text())
        self.assertIn('renderer_main.cc', d['why_renderer_sandbox_disabled']['source'])
        self.assertEqual(d['nt51_capability_matrix']['integrity_levels_low_IL'][:11], 'UNAVAILABLE')
        self.assertIn('process-tree containment', d['xp25_containment_architecture']['model'])

if __name__ == '__main__':
    unittest.main()
