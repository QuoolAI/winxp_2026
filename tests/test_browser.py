"""Security and reproducibility gates for browser integration; guest acceptance
is recorded separately under .work, never inferred from these host checks."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build'))
sys.path.insert(0,str(ROOT/'vm'))
from prepare_browser import verified_package
from browser_config import generate
from check_browser_update import report
from browser_matrix import serial_markers

class BrowserPackageTests(unittest.TestCase):
    def test_guest_exit_parser_keeps_numbered_prefix_and_crash_exit(self):
        text='XP25_BROWSER_INSTALL_EXIT=0\r\nXP25_BROWSER_PROCESS_EXIT=-36863\r\nXP25_SHELLEXECUTE_REJECTED_SCHEME=87\r\nnot a marker=0\n'
        self.assertEqual(serial_markers(text),{'XP25_BROWSER_INSTALL_EXIT':'0','XP25_BROWSER_PROCESS_EXIT':'-36863','XP25_SHELLEXECUTE_REJECTED_SCHEME':'87'})

    def fixture(self,directory,members):
        p=Path(directory)/'release.zip'
        with zipfile.ZipFile(p,'w') as z:
            for name,data in members.items():z.writestr(name,data)
        return p,{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}

    def test_package_digest_is_enforced(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as d:
            p,pin=self.fixture(d,{'Supermium/chrome.exe':b'fixture, never executed'})
            verified_package(p,pin)
            data=bytearray(p.read_bytes());data[30]^=1;p.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'pinned official asset'):verified_package(p,pin)

    def test_archive_traversal_is_rejected_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as d:
            p,pin=self.fixture(d,{'Supermium/chrome.exe':b'fixture','../escape.exe':b'no'})
            with self.assertRaisesRegex(ValueError,'unsafe archive member'):verified_package(p,pin)
            self.assertFalse((Path(d).parent/'escape.exe').exists())

    def test_registration_keeps_security_controls_and_records_rollback(self):
        pin=json.loads((ROOT/'components/browser/release.json').read_text())
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as d:
            out=Path(d);generate(out,pin,True)
            registry=(out/'associations.reg').read_text(encoding='utf-16')
            # The native launcher adds --disable-gpu from this DWORD; no browser
            # command line with switches is stored in the registry.
            self.assertIn('"SoftwareRendering"=dword:00000001',registry)
            self.assertIn('XP25.URL',registry)
            self.assertIn('opennewwindow',registry)
            self.assertNotIn('--single-argument',registry)
            self.assertIn('open-url',registry)
            self.assertIn('open-document',registry)
            for forbidden in ['no-sandbox','ignore-certificate','disable-encryption','disable-web-security']:
                self.assertNotIn(forbidden,registry)
            self.assertIn('key-restore',(out/'rollback.cmd').read_text())
            self.assertIn('super0.absent',(out/'rollback.cmd').read_text())
            scope=json.loads((out/'registration-scope.json').read_text())
            self.assertTrue(all(root in ['HKLM','HKCU'] for root,_ in scope))

    def test_update_check_is_metadata_only_and_rejects_unofficial_assets(self):
        pin={'version':'1','tag':'v1'}
        release={'tag_name':'v2','name':'2','draft':False,'prerelease':False,'assets':[{'name':'supermium_2_32_nonsetup.zip','browser_download_url':'https://github.com/win32ss/supermium/releases/download/v2/supermium_2_32_nonsetup.zip','size':1,'digest':'sha256:'+'0'*64}]}
        r=report(pin,release)
        self.assertTrue(r['different_release_available'])
        self.assertEqual(r['action'],'read_only');self.assertFalse(r['installation_authorized'])
        release['assets'][0]['browser_download_url']='https://unofficial.invalid/package.zip'
        with self.assertRaises(ValueError):report(pin,release)
        release['prerelease']=True
        with self.assertRaises(ValueError):report(pin,release)

    def test_gateway_policy_routes_everything_through_the_gateway(self):
        pin=json.loads((ROOT/'components/browser/release.json').read_text())
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as d:
            blocked=Path(d)/'blocked';gateway=Path(d)/'gateway';blocked.mkdir();gateway.mkdir()
            generate(blocked,pin,True);generate(gateway,pin,True,'gateway')
            old=(blocked/'associations.reg').read_text(encoding='utf-16');new=(gateway/'associations.reg').read_text(encoding='utf-16')
            self.assertIn('URLBlocklist',old);self.assertNotIn('ProxyServer',old)
            self.assertNotIn('URLBlocklist',new)
            for line in ['"ProxyMode"="fixed_servers"','"ProxyServer"="10.25.0.1:3128"','"HttpsOnlyMode"="force_enabled"']:self.assertIn(line,new)
            # Named after its program, or Explorer registers XP25Browser.exe as a legacy client of its own.
            self.assertIn('[HKEY_LOCAL_MACHINE\\SOFTWARE\\Clients\\StartMenuInternet\\XP25Browser.exe\\shell\\open\\command]',new)
            self.assertIn('@="XP25Browser.exe"',new)
            with self.assertRaises(ValueError):generate(Path(d),pin,True,'open')

    def test_ie_removal_deletes_the_engine_and_keeps_what_explorer_needs(self):
        import ie_removal
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as d:
            record=ie_removal.generate(d);cmd=(Path(d)/'remove-ie.cmd').read_text()
            for name in ['mshtml.dll','jscript.dll','vbscript.dll','mshta.exe','inetcpl.cpl']:
                self.assertIn('delete-at-boot "%S%\\'+name+'"',cmd)
                self.assertIn('delete-at-boot "%S%\\dllcache\\'+name+'"',cmd)
            self.assertIn('delete-at-boot "%S%\\dllcache\\iexplore.exe"',cmd)
            for kept in ['wininet.dll','urlmon.dll','shdocvw.dll','browseui.dll','ieframe.dll','iertutil.dll']:
                self.assertNotIn(kept,cmd);self.assertIn(kept,record['kept'])
            # ieproxy.dll marshals Explorer's own interfaces: the IE folder loop skips it.
            self.assertIn('if /i not "%%~nxF"=="ieproxy.dll"',cmd)
            # COM registrations go before the files are queued; each || stays with its own command.
            self.assertLess(cmd.index('unregister-file "%S%\\mshtml.dll"'),cmd.index('XP25_IE_STEP=schedule'))
            self.assertNotIn(' || exit /b 5\r\n',''.join(l+'\r\n' for l in cmd.splitlines() if l.startswith('if exist')))
            machine=(Path(d)/'remove-ie.reg').read_text(encoding='utf-16');user=(Path(d)/'remove-ie-user.reg').read_text(encoding='utf-16')
            self.assertIn('[-HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE]',machine)
            for component in ie_removal.ACTIVE_SETUP:self.assertIn('Installed Components\\'+component+']',machine)
            self.assertIn('"nusrmgr.cpl"="no"',machine);self.assertIn('xp25users.cpl"=dword:00000009',machine)
            self.assertIn('"Use Search Asst"="no"',user)
            self.assertIn('HKEY_USERS\\XP25IE',(Path(d)/'remove-ie-hive.reg').read_text(encoding='utf-16'))
if __name__=='__main__':unittest.main()
