#!/usr/bin/env python3
"""Prepare only independent XP25 Winlogon sources in private native build media."""
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
 if not out.is_relative_to(ROOT/'.work'):p.error('private output required')
 out.mkdir(parents=True,exist_ok=False);media=out/'media';(media/'winlogon').mkdir(parents=True)
 for source in (ROOT/'components/winlogon').iterdir():
  if source.is_file():shutil.copy2(source,media/'winlogon'/source.name)
 (media/'build.cmd').write_bytes((ROOT/'build/native-winlogon-build.cmd').read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
 command=['xorriso','-as','mkisofs','-quiet','-iso-level','3','-J','-R','-V','XP25WL','-o',str(out/'native-winlogon.iso'),str(media)]
 subprocess.run(command,check=True)
 (out/'manifest.json').write_text(json.dumps({'command':command,'files':{str(f.relative_to(media)):hashlib.sha256(f.read_bytes()).hexdigest() for f in media.rglob('*') if f.is_file()},'scope':'Independent XP25 sources only; original NT reference tree unchanged.'},indent=2)+'\n')
 print(out/'native-winlogon.iso')
if __name__=='__main__':main()
