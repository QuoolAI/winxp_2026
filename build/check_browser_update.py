#!/usr/bin/env python3
"""Read-only official Supermium update check for the XP25 management workflow.
Fetches release metadata only; never downloads, executes or installs a package.
The installed pin is registry-readable by ClippyAI without opening browser data.
"""
import argparse
import datetime
import json
from pathlib import Path
import urllib.request


def report(installed,release):
    assets=[{'name':a['name'],'url':a['browser_download_url'],'bytes':a['size'],'digest':a.get('digest')} for a in release.get('assets',[]) if a['name'].endswith('_32_nonsetup.zip')]
    if release.get('draft') or release.get('prerelease') or len(assets)!=1:raise ValueError('not a stable official x86 release')
    asset=assets[0]
    expected='https://github.com/win32ss/supermium/releases/download/'+release['tag_name']+'/'
    if not asset['url'].startswith(expected) or not (asset['digest'] or '').startswith('sha256:'):raise ValueError('official asset provenance/digest incomplete')
    return {'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'installed_version':installed['version'],'installed_tag':installed['tag'],'latest_tag':release['tag_name'],'latest_name':release['name'],'different_release_available':release['tag_name']!=installed['tag'],'asset':asset,'action':'read_only','installation_authorized':False,'instructions':'Verify release compatibility and package SHA-256, then obtain explicit update authorization. Browser profile data is never consulted.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--pin',type=Path,required=True);p.add_argument('--release-json',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if '.work' not in a.output.resolve().parts:p.error('private .work report required')
    if a.release_json:release=json.loads(a.release_json.read_text())
    else:
        request=urllib.request.Request('https://api.github.com/repos/win32ss/supermium/releases/latest',headers={'Accept':'application/vnd.github+json','User-Agent':'XP25-readonly-browser-check'})
        with urllib.request.urlopen(request,timeout=30) as r:release=json.load(r)
    result=report(json.loads(a.pin.read_text()),release)
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
