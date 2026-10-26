#!/usr/bin/env python3
"""Verify the pinned official browser and prepare private guest installation media.
No downloaded code is executed on the build host. No source/binary is uploaded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()

def verified_package(package, pin):
    if package.stat().st_size != pin['bytes'] or sha(package) != pin['sha256']:
        raise ValueError('browser package does not match the pinned official asset')
    with zipfile.ZipFile(package) as z:
        if sum(i.file_size for i in z.infolist()) > 1500000000:raise ValueError('oversized archive')
        seen=set()
        for i in z.infolist():
            p=Path(i.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in i.filename or ':' in i.filename or (i.external_attr>>16)&0o170000 == 0o120000:
                raise ValueError('unsafe archive member: '+i.filename)
            if i.filename.lower() in seen:raise ValueError('duplicate archive member')
            seen.add(i.filename.lower())
        if 'Supermium/chrome.exe' not in z.namelist():raise ValueError('missing browser')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--browserctl',type=Path,required=True)
    p.add_argument('--pin',type=Path,default=ROOT/'components/browser/release.json')
    p.add_argument('--download',action='store_true')
    p.add_argument('--software-rendering',action='store_true',help='verified engineering VGA profile only')
    a=p.parse_args();out=a.output.resolve();package=a.package.resolve()
    if not out.is_relative_to(ROOT/'.work') or not package.is_relative_to(ROOT/'.work'):p.error('private .work paths required')
    pin=json.loads(a.pin.read_text())
    if a.download and not package.exists():
        package.parent.mkdir(parents=True,exist_ok=True)
        with urllib.request.urlopen(pin['url'],timeout=60) as r,package.with_suffix('.partial').open('wb') as f:shutil.copyfileobj(r,f)
        package.with_suffix('.partial').rename(package)
    verified_package(package,pin)
    out.mkdir(parents=True,exist_ok=False);media=out/'media';media.mkdir()
    with zipfile.ZipFile(package) as z:z.extractall(media)
    # Portable convenience launchers disable local credential encryption. They
    # are retained in the verified archive, never installed as XP25 entry points.
    excluded=[]
    for launcher in (media/'Supermium').glob('*.cmd'):
        excluded.append(str(launcher.relative_to(media)));launcher.unlink()
    shutil.copy2(a.browserctl,media/'browserctl.exe')
    from browser_config import generate,installation_suite
    generate(media,pin,a.software_rendering)
    (out/'install-suite.cmd').write_bytes(installation_suite())
    for name in ('local.html',):
        src=ROOT/'components/browser'/name
        shutil.copy2(src,media/name)
    manifest={'pin':pin,'package':str(package),'package_sha256':sha(package),'software_rendering':a.software_rendering,'excluded_portable_launchers':excluded,'install_suite_sha256':sha(out/'install-suite.cmd'),'files':{str(f.relative_to(media)):sha(f) for f in sorted(media.rglob('*')) if f.is_file()},'redistribution_approved':False}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    cmd=['genisoimage','-quiet','-J','-joliet-long','-r','-V','XP25BROWSER','-o',str(out/'browser.iso'),str(media)]
    (out/'commands.json').write_text(json.dumps([cmd],indent=2)+'\n')
    subprocess.run(cmd,check=True)
    print(json.dumps({'iso':str(out/'browser.iso'),'sha256':sha(out/'browser.iso')}))
if __name__=='__main__':main()
