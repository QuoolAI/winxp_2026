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
if __name__=='__main__':unittest.main()
