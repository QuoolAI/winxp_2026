#!/usr/bin/env python3
"""Recover original Winlogon in a NEW child of the pre-experiment checkpoint.

Never opens a reference or running guest writable. A failed Winlogon boot can
leave NTFS unclean. Preserve that overlay and roll back its experiment writes;
do not force an offline write through its unreplayed journal.
"""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
import xp_lab as lab
ROOT=Path(__file__).resolve().parents[1]
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for c in iter(lambda:f.read(1024*1024),b''):h.update(c)
 return h.hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--experiment',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 source,out=a.experiment.resolve(),a.output.resolve()
 if any(not f.is_relative_to(ROOT/'.work') for f in (source,out)):p.error('private paths required')
 disk=source/'disk.qcow2'
 if disk.stat().st_mode&0o222:p.error('experiment must be stopped and frozen')
 failure=json.loads((source/'failure.json').read_text());inputs=json.loads((source/'inputs.json').read_text())
 if failure.get('accepted') is not False:p.error('explicit rejected experiment required')
 recovery=inputs['recovery'];target='/WINDOWS/system32/winlogon.exe'
 if not recovery or recovery['target']!=target:p.error('one recorded Winlogon replacement required')
 original=Path(recovery['host_backup']).resolve()
 if not original.is_relative_to(source) or sha(original)!=recovery['original_sha256']:p.error('original recovery bytes do not match')
 base=Path(inputs['base']).resolve()
 if not base.is_relative_to(ROOT/'.work') or base.stat().st_mode&0o222 or sha(base)!=inputs['base_sha256']:
  p.error('pre-experiment checkpoint must remain frozen and hash-identical')
 before=sha(disk);out.mkdir(parents=True,exist_ok=False);os.chdir(out)
 lab.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',base,'disk.qcow2'])
 with lab.partition(out/'disk.qcow2',True) as device:
  current=lab.run(['ntfscat',device,target])
  if hashlib.sha256(current).hexdigest()!=recovery['original_sha256']:raise ValueError('checkpoint does not contain recorded original Winlogon')
  lab.run(['ntfscp','-t',device,original,'/xp25/recovery-winlogon.exe'])
  if lab.run(['ntfscat',device,'/xp25/recovery-winlogon.exe'])!=original.read_bytes():raise ValueError('recovery copy readback failed')
 if sha(disk)!=before:raise ValueError('rejected parent changed')
 if sha(base)!=inputs['base_sha256']:raise ValueError('verified checkpoint changed')
 (out/'image-check.log').write_bytes(lab.run(['qemu-img','check','disk.qcow2']))
 (out/'disk.qcow2').chmod(0o444)
 manifest={'source':str(source),'source_sha256':before,'target':target,'original_sha256':sha(original),
  'restored_disk_sha256':sha(out/'disk.qcow2'),'registry_changes':[],'boot_configuration_changes':[],
  'parent_was_rejected':True,'guest_boot':'not_yet_tested','command':__import__('sys').argv,
  'method':'rollback_to_verified_pre_experiment_checkpoint','base':str(base),
  'base_sha256':inputs['base_sha256'],'failed_experiment_writes_rolled_back':True,
  'failed_overlay_preserved':True,'unclean_ntfs_journal_was_not_forced':True}
 (out/'recovery.json').write_text(json.dumps(manifest,indent=2)+'\n');print(out/'disk.qcow2')
if __name__=='__main__':main()
