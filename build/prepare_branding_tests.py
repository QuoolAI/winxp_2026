#!/usr/bin/env python3
"""Package local branding probes and a registry-only MSI compatibility fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--core-media', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private media required')
    result = json.loads((args.probe / 'result.json').read_text())
    if (result['status'] != 'compiled_static_checks_passed' or result['source_sha256'] != sha(ROOT / 'tests/guest/branding_probe.c') or
            result['executable_sha256'] != sha(args.probe / 'branding_probe.exe')):
        parser.error('branding probe is stale or unverified')
    output.mkdir(parents=True, exist_ok=False)
    media = output / 'media'
    shutil.copytree(args.core_media, media)
    shutil.copy2(args.probe / 'branding_probe.exe', media / 'branding_probe.exe')
    (media / 'identity.cmd').write_bytes(b'@echo off\r\nD:\\branding_probe.exe %1\r\necho BRANDING_PROBE_EXIT=%ERRORLEVEL% > COM1\r\nver > C:\\xp25\\cmd-version.txt\r\n')
    folder = media / 'msi'
    folder.mkdir()
    def table(name, headers, types, keys, rows):
        lines = [headers, types, keys] + rows
        (folder / (name + '.idt')).write_bytes(('\r\n'.join('\t'.join(row) for row in lines) + '\r\n').encode('cp1252'))
    table('_SummaryInformation', ['PropertyId','Value'], ['i2','l255'], ['_SummaryInformation','PropertyId'], [
        ['1','1252'],['2','XP25 local compatibility fixture'],['3','Registry-only installation test'],
        ['4','XP25 project'],['7','Intel;1033'],['9','{603BE336-0B25-4B4C-8225-2A68C43DD933}'],['14','100'],['15','0']])
    table('Property',['Property','Value'],['s72','l0'],['Property','Property'],[
        ['ProductCode','{29A903CB-6A25-4A18-8E25-716FB47631B7}'],['ProductName','XP25 Branding Compatibility Fixture'],
        ['ProductVersion','1.0.0'],['ProductLanguage','1033'],['Manufacturer','XP25 project'],['INSTALLLEVEL','1'],['ARPNOMODIFY','1'],['ARPNOREPAIR','1']])
    table('Directory',['Directory','Directory_Parent','DefaultDir'],['s72','S72','l255'],['Directory','Directory'],[
        ['TARGETDIR','','SourceDir'],['APPDIR','TARGETDIR','XP25BrandingFixture']])
    table('Media',['DiskId','LastSequence','DiskPrompt','Cabinet','VolumeLabel','Source'],
        ['i2','i2','L64','S255','S32','S32'],['Media','DiskId'],[['1','0','','','','']])
    table('Component',['Component','ComponentId','Directory_','Attributes','Condition','KeyPath'],
        ['s72','S38','s72','i2','S255','S72'],['Component','Component'],[
        ['FixtureComponent','{58C643F5-0525-4D40-8E25-C8A98257139D}','APPDIR','4','','FixtureReg']])
    table('Feature',['Feature','Feature_Parent','Title','Description','Display','Level','Directory_','Attributes'],
        ['s38','S38','L64','L255','I2','i2','S72','i2'],['Feature','Feature'],[
        ['Complete','','Compatibility fixture','Local registry-only branding regression test','2','1','APPDIR','0']])
    table('FeatureComponents',['Feature_','Component_'],['s38','s72'],['FeatureComponents','Feature_','Component_'],[['Complete','FixtureComponent']])
    table('Registry',['Registry','Root','Key','Name','Value','Component_'],['s72','i2','l255','L255','L0','s72'],['Registry','Registry'],[
        ['FixtureReg','1','Software\\XP25MsiBrandingFixture','Installed','#1','FixtureComponent']])
    table('LaunchCondition',['Condition','Description'],['s255','l255'],['LaunchCondition','Condition'],[
        ['VersionNT = 501 AND NOT VersionNT64','This fixture requires native x86 Windows NT 5.1.']])
    actions=[('LaunchConditions',100),('CostInitialize',800),('FileCost',900),('CostFinalize',1000),('InstallValidate',1400),
        ('InstallInitialize',1500),('ProcessComponents',1600),('UnpublishFeatures',1800),('RemoveRegistryValues',2600),
        ('WriteRegistryValues',5000),('RegisterProduct',6100),('PublishFeatures',6300),('PublishProduct',6400),('InstallFinalize',6600)]
    table('InstallExecuteSequence',['Action','Condition','Sequence'],['s72','S255','I2'],['InstallExecuteSequence','Action'],[[a,'',str(n)] for a,n in actions])
    script = '''Option Explicit
Dim installer, db, fso, path, tables, name
path = "C:\\xp25\\branding-fixture.msi"
Set fso = CreateObject("Scripting.FileSystemObject")
If fso.FileExists(path) Then fso.DeleteFile path, True
Set installer = CreateObject("WindowsInstaller.Installer")
Set db = installer.OpenDatabase(path, 3)
tables = Array("_SummaryInformation", "Property", "Directory", "Media", "Component", "Feature", "FeatureComponents", "Registry", "LaunchCondition", "InstallExecuteSequence")
For Each name In tables
  db.Import "D:\\msi", name & ".idt"
Next
db.Commit
WScript.Echo "XP25 fixture MSI database created"
'''
    (media / 'msi-build.vbs').write_bytes(script.replace('\n','\r\n').encode('ascii'))
    batch = r'''@echo off
cscript //nologo D:\msi-build.vbs > C:\xp25\msi-build.log 2>&1
echo MSI_BUILD_EXIT=%ERRORLEVEL% > COM1
if errorlevel 1 exit /b 1
msiexec /i C:\xp25\branding-fixture.msi /qn /norestart /l*v C:\xp25\msi-install.log
echo MSI_INSTALL_EXIT=%ERRORLEVEL% > COM1
D:\branding_probe.exe --msi-installed
echo MSI_INSTALLED_STATE_EXIT=%ERRORLEVEL% > COM1
msiexec /x C:\xp25\branding-fixture.msi /qn /norestart /l*v C:\xp25\msi-uninstall.log
echo MSI_UNINSTALL_EXIT=%ERRORLEVEL% > COM1
D:\branding_probe.exe --msi-absent
echo MSI_UNINSTALLED_STATE_EXIT=%ERRORLEVEL% > COM1
echo MSI_FIXTURE_FINISHED > COM1
'''
    (media / 'msi-test.cmd').write_bytes(batch.replace('\n','\r\n').encode('ascii'))
    (media / 'verify-branding.cmd').write_bytes(
        b'@echo off\r\ncall D:\\identity.cmd %1\r\ncall D:\\msi-test.cmd\r\ncall D:\\arm-shutdown.cmd\r\necho BRANDING_SUITE_FINISHED > COM1\r\n')
    (media / 'refresh-menu.vbs').write_bytes(
        (ROOT / 'branding/refresh-menu.vbs').read_text(encoding='ascii').replace('\n', '\r\n').encode('ascii'))
    command=['genisoimage','-quiet','-J','-r','-o',str(output / 'branding-tests.iso'),str(media)]
    subprocess.run(command,check=True)
    (output / 'manifest.json').write_text(json.dumps({'prepare_command':[sys.executable,*sys.argv], 'command':command,'probe_source_sha256':result['source_sha256'],
        'files':{str(p.relative_to(media)):sha(p) for p in media.rglob('*') if p.is_file()},
        'msi_scope':'Own registry-only product; no system files, OS identity or licensing keys are authored.'},indent=2)+'\n')
    print(output / 'branding-tests.iso')


if __name__ == '__main__':
    main()
