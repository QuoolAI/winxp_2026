# XP25-Winlogon OEM branding (QuoolAI)

On 2026-10-25 the third-party OEM branding in the **XP25-Winlogon** virt-manager VM
was replaced. The change went to that VM's own writable disk,
`.work/virt-manager-XP25-Winlogon-20261025/XP25-Winlogon-Desktop.qcow2` in the main
checkout.
That disk is a standalone copy. The frozen engineering image it was copied from
(`engineering-image-02`, `0df7fc05…c51c`) and every other image are unchanged.

`C:\WINDOWS\system32\oeminfo.ini` now contains exactly:

```ini
[General]
Manufacturer=QuoolAI
Model=Windows XP 25th Anniversary Edition
```

The file is 76 bytes, ASCII with CRLF line endings, SHA-256
`7760193a85f4a23f78d61a9367ffc6f2bd21c81b9f593feb02fc6999b3dfe5fc`.

**Update:** the clipping described here was fixed by widening the line in `sysdm.cpl`, and XP25-AI received the same branding ([xp25-vm-configuration.md](xp25-vm-configuration.md)).

**Result:** System Properties shows **QuoolAI** and the new model. The model line
is too long for its fixed-width field, though, so only "Windows XP 25th
Anniversary" is visible (see [Display limit](#display-limit-the-model-line-is-clipped)).
The guest's own check passes 15 of 16 cases; the failing one is this clipping.

## What was there before

| Item | Before | After |
| --- | --- | --- |
| `system32\OEMINFO.INI` | 68 bytes, `a1052310…eaee`: a third-party `Manufacturer` and a web address as `Model`, no `[Support Information]` | The file above |
| OEM logo (`system32\oemlogo.bmp`, Win9x `system\oemlogo.bmp`) | Absent | Absent; there was no logo to remove |
| `HKLM\SOFTWARE\Microsoft\PCHealth\HelpSvc\OEMInfo` | `Manufacturer`/`Model` with the third-party values, no `Text` | `QuoolAI` / `Windows XP 25th Anniversary Edition`, no `Text` |
| My Computer `OEMLinks` key | Absent | Absent |

The HelpSvc key is Help and Support Center's own copy of the `oeminfo.ini` values.
HelpSvc's install step copies `[General]` Manufacturer and Model (and
`[Support Information]` lines into `Text`) into it
(`admin/pchealth/helpctr/service/core/setup.cpp`, `Local_Install`). The support
page reads it directly (`content/systempages/blurbs/isupport.htm`). HelpSvc does
not refresh it at boot, so changing only the file would have left the
third-party name in Help and Support. It was updated in the guest with `reg.exe`;
no hive was patched offline.

System Properties reads `[General]` Manufacturer and Model from
`%windir%\system32\oeminfo.ini` into the Computer lines of the General page. It
shows a logo only when `oemlogo.bmp` exists (`shell/cpls/system/general.cpp`,
`CompleteGeneralDlgInitialization`).

A read-only raw scan of the whole NTFS partition before the change
(`scan-winlogon-before-02`, ASCII and UTF-16LE, case-insensitive) found the
branding text in only four places:
- `$MFT` (the resident data of `OEMINFO.INI`).
- The live `software` hive.
- `WINDOWS\repair\software`.
- One unallocated cluster.

The other "maher" hits are ordinary words in Search Assistant's lexicon
(`WINDOWS\srchasst\nls302en.lex`) and in the guest's `\nt` source tree.

## Backups

Taken before any change, in the guest by native tools and on the host:

- Guest, `C:\xp25\oem-backup-20261025\`:
  - `OEMINFO.INI.original`: a byte copy, 68 bytes, verified identical offline.
  - `HelpSvc-OEMInfo.original.reg`: `reg export` of the key, 352 bytes, SHA-256 `6f14a6ac…395c`.
  - `restore-original-oem.cmd`: copies the file back and `reg import`s the export.
- Host, `.work/oem-branding-20261025/winlogon-vm-01/offline/`:
  - `original-OEMINFO.INI`.
  - `guest-HelpSvc-OEMInfo.original.reg`.
  - The guest's before-check record, `guest-check-before.json`.

To undo the change, log on as an administrator, run
`C:\xp25\oem-backup-20261025\restore-original-oem.cmd`, then reopen System
Properties. The script was exercised on the rehearsal disk: afterwards System
Properties and HelpSvc showed the third-party values again.

## Procedure

1. **Rehearsal** on a disposable overlay of the VM's disk (`rehearsal-01`), with
   the same KVM profile, no NIC and a host-readable COM1. It ran the whole
   procedure plus the restore test across three boots, each ending in a
   guest-requested shutdown. Its first after-check showed the clipped model line,
   so a fit measurement was added to the probe (media-04) and the flow was run
   again.
2. **Boot 1** of the real VM. Started with `virsh start`; media-04 was inserted
   live with `virsh change-media`. Logged on as `XP25`, then `D:\oem-before.cmd`:
   - made the backups;
   - ran `oem_probe.exe` in observe mode, which recorded the third-party
     manufacturer and model in System Properties.

   Start → Turn Off Computer → Turn Off. libvirt reported `Shutdown Finished
   after guest request` and `shut off (shutdown)`.
3. **Offline write** of the shut-off disk (`apply_offline.py`). It writes
   nothing unless every precondition holds:
   - the NTFS volume flags are `0x0000`;
   - the current file is the recorded original;
   - the guest backups, registry export, restore script and before-check are present, with exit codes 0;
   - no logo file exists;
   - all 22 XP25 components match the VM's registration record.

   Then it replaces only `OEMINFO.INI` with `ntfscp`; no `--force` was used, and
   ntfs-3g refuses an unclean or hibernated volume. Afterwards it confirms:
   - readback equals the new text;
   - there is a single `oeminfo.ini` entry;
   - the 22 components plus `sysdm.cpl`, `xpsp1res.dll`, `winver.exe`,
     `shell32.dll`, `logonui.exe`, `explorer.exe`, `oembios.bin/.dat/.sig`,
     `licdll.dll` and `wpa.dbl` are unchanged;
   - `qemu-img check` passes.

   All 13 checks passed.
4. **Boot 2.** Logon, then `D:\oem-apply.cmd`: `reg add` of the two HelpSvc
   values (both exit 0), then `oem_probe.exe --expect`. Guest-requested shutdown
   again. The guest's records were then read offline.
5. **Boot 3 (hand-off).** Plain `virsh start` with no media. Logged on, opened
   System Properties with Win+Pause, and left it running.

The VM was driven only through libvirt's public API (`send-key`, `screenshot`,
`change-media --live`, lifecycle events), not monitor commands. Its persistent
definition is byte-identical before and after (SHA-256 `9590418c…fa3`), with the
CD-ROM empty. Disk SHA-256 before the change:
`6c85a95da33c36b6c3d2f1c222858ec1f7d53646e88c188653a328dc51becd15`. libvirt's
stored reason for the previous stop was already `shutdown`.

## Guest verification (`check-after.json`, boot 2)

`tests/guest/oem_probe.c` (`build/guest.py --probe oem`, SHA-256 `d4ddc115…2cbd`,
reproducible) reads the file and the registry, then opens System Properties
(`rundll32 shell32.dll,Control_RunDLL sysdm.cpl,,0`). It waits for the
asynchronous General page to finish and records every control's text. The VM's
COM1 file is root-only, so the probe wrote its JSON lines to `C:\xp25\oem-check-20261025`,
and they were read offline after the guest shut down.

| Case | Result |
| --- | --- |
| `oeminfo_manufacturer_quoolai`, `oeminfo_model_xp25` | pass |
| `oeminfo_no_support_section`, `oem_logo_absent`, `oeminfo_no_third_party_text` | pass |
| `helpsvc_oeminfo_matches`, `helpsvc_no_third_party_text` | pass |
| `nt51_x86_identity` (5.1.2600 SP3 workstation x86), `product_name_windows_xp` | pass |
| `system_properties_opened`, `system_properties_manufacturer_then_model` (controls 63 → 64) | pass |
| `system_properties_no_third_party_text`, `system_properties_manufacturer_fully_visible` | pass |
| `system_properties_model_fully_visible` | **fail**: 179 px of text in a 165 px control |

Comparing the before and after records, the only System Properties texts that
changed are controls 63 and 64. The other 19 are identical: the XP25 label
"Windows XP 25th Anniversary Edition" beside the logo, "Microsoft Windows XP /
Professional / Version 2002 (Debug) / Service Pack 3", the registered user and
Product ID, and the processor and memory lines. Help and Support's support page
itself was not opened.

Offline after boot 2 (`verify-after.json`):
- `OEMINFO.INI` has the new hash.
- The HelpSvc values are the QuoolAI ones, and no live registry value contains the third-party name.
- The 22 components still match the registration record.
- Every preserved file is unchanged from the offline step.

Licensing was not reconfigured. The logons on boots 1–3 reached the desktop
through the independent Winlogon, whose `licdll` admission fails closed. The
rehearsal's COM1 records `licensing_policy_verified` and `licensing_policy_allowed`
on every boot.

## Display limit: the model line is clipped

**Fixed later on 2026-10-25:** the branded `sysdm.cpl` now widens these lines to 124 DLU, and both VMs show the full model ([xp25-vm-configuration.md](xp25-vm-configuration.md)). The rest of this section describes the state before that fix.

The General page's Computer lines are fixed-width `Link Window` controls,
165 px at 96 DPI. In Tahoma 8 pt, "Windows XP 25th Anniversary Edition" is 179 px
wide, so System Properties shows "Windows XP 25th Anniversary". This is visible
in `boot2-03-after-sysdm.png` and in the hand-off `boot3-02-system-properties.png`.
The control holds the full text: `WM_GETTEXT` returns it, and the registry and
file are exact.

The width was measured with the system message font, because sysdm's font handle
cannot be read from another process (`font_method` 2). The screenshots agree with it.
Fitting the text needs either a shorter Model value or a wider line in XP25's
branded `sysdm.cpl` dialog resource. The first changes the requested text and the
second changes the XP25 branding, so neither was done.

## Residual copies and limits

- `WINDOWS\repair\software` still holds the old HelpSvc values. It is the repair
  hive Setup saved, and Windows does not read it while running. Free cells in
  the live hive and one unallocated cluster may also still hold the old bytes.
  None of this is displayed, and patching hives offline was not attempted.
- The same third-party `OEMINFO.INI` is present in other images, including the AI image-05
  that the new XP25-AI VM uses ([virt-manager-xp25-ai.md](virt-manager-xp25-ai.md)).
  Only XP25-Winlogon was changed, as requested.
- The VM runs at 640×480; the clipping is the same at any resolution at 96 DPI.
  Other DPI settings were not tested.

## Evidence

All under `.work/oem-branding-20261025/`:

- `inspect-winlogon-03/`: the first read-only inspection: OEM files, hives and the
  system32 listing. Runs `-01` and `-02` stopped on path-casing bugs and are kept.
- `scan-winlogon-before-02/scan.json`: the raw scan. The first, Python-regex
  scan was interrupted at 23 of 34 GB because it was CPU-bound; it is kept with
  `aborted.json`.
- `rehearsal-01/`: three serial logs, screenshots, offline results and `shutdown-event-0{1,2,3}.json`.
- `media-0{1..4}`: the probe and scripts. Media 01–03 are kept with `SUPERSEDED.json`.
- `winlogon-vm-01/`:
  - `commands.jsonl`: every libvirt call.
  - `shutdown-event-0{1,2}.json`.
  - `offline/result.json`: the 13 checks and their hashes.
  - `verify-after/`: `check-after.json`, `apply.log`, `verify-after.json` and `sysdm-text-compare.json`.
  - Screenshots `boot1-*`, `boot2-*` and `boot3-*`.
