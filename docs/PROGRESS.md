# Development progress

## Current checkpoint

2026-11-23, MerlinAI on the XP25-Winlogon-Fix VM; native build 12. The VM's
disk is now image-04 (`378e9edd…8183`, MerlinAI build 10; the previous disk is
kept as `XP25-Winlogon-Fix.supermium.qcow2`). Its NIC filter
`xp25-browser-merlin` adds the relay (8740) and deployment-agent (8746) ports.
It is enrolled as `xp25-winlogon-fix` (builder baseline `xp25wf4`, its own
builder credential). Observed in the VM: two authenticated health reports
(one before any logon); the Control Panel with MerlinAI and without Security
Center or Automatic Updates; the builder answering through the relay; a
normal guest-requested turn-off. Disk afterwards `55723697…c082`. No update
was built or applied on it. An enrolled existing VM needs
`merlin_deploy_agent.py adopt`, which `enroll_vm.py` now prints. Build 11
failed 20/24 under TCG: Windows refused the crash dialog the foreground,
because since build 10 the crashed program had already been ended. Native
build 12 takes the foreground first: 9A 24/24 under UP and MP, TCG 24/24.
The VM keeps build 10 (its dialog can come up without keyboard focus).
[VM deployment](merlinai-milestone9.md#deployment-to-the-xp25-winlogon-fix-vm-2026-11-2223),
[build 12](merlin-dialog-readiness.md). The image-04 switch oracle's first run
failed 3/5 (a Found New Hardware wizard took the keys) and is kept; the
repetition passed 9/9.

2026-11-22/23, MerlinAI continuation in the main checkout. Reconciled the
unfinished M9 record against retained guest evidence. Native build 10's
image-04 (`378e9edd…8183`) passes boot/logon/desktop/status/normal turn-off
6/6 under UP, MP and TCG; screen saver 10/10; nine painted account switches;
security 34/35 (four inherited USB-driver findings). Browser aggregate remains
23/26, with Remote Registry disabled and explicit coverage gaps; DevTools
11/11, persistence, MSI and AI checks pass. The retained model job on baseline
`xp25wf4` is ready with its controlled repair tested under nested UP/MP/TCG.
These are recorded private lab results; registered-VM deployment is pending.

Build 10's 9A MP run passed 21/24 because automation used the capture marker
before the crash dialog was initialized. Added a dialog-readiness marker and
wait for it in the harness. All 26 MerlinAI host tests pass; native build 11
is accepted with 52 source matches, six outputs and checked guest imports.
The focused two-vCPU KVM 9A rerun passes 24/24, including consented transfer
and guest-requested normal shutdown. Build 11 is not packaged or deployed.
[Focused evidence, commands and runtime result](merlin-dialog-readiness.md).
No change to `Source/`, registered VM disks, running builder or remote branches.

2026-11-22, worktrees consolidated. Every branch is contained in `xp25-nt`
(pushed together with `xp25-merlin`). The checkouts of `xp25-ai`,
`xp25-security`, `xp25-cve`, `xp25-winlogon-ui` and `xp25-modernization`
were removed after checking that each was clean and contained. Each held its
own 6 GB copy of `Source/`; free space went from 19 GB to 49 GB. Their
`.work/` evidence and VM disks stay in place, because VMs and backing chains use
those absolute paths. Where each milestone's evidence now lives:
[evidence-locations.md](evidence-locations.md). The browser gateway's user
service was repointed to the main checkout; the XP25-Winlogon-Fix VM it
serves was off. `xp25-merlin` stays a worktree for the running MerlinAI
services and VMs. `builder_vm.py provider` installs a model-provider key on
the MerlinAI builder without it passing through the host's files.

2026-11-21, Milestone 9 MerlinAI (`xp25-merlin`, commits `abd27bd87` 9A,
`7da02d0dc` 9B/9C, `39c4e3848`, `829956389`, `8069b7d4c`; evidence
`.work/merlin-20261121/`). MerlinAI replaces Microsoft error reporting and the
Security Center and Automatic Updates pages with a user-driven repair loop:
crash dialog → local queue → Control Panel → Build an Update on a separate
builder VM → reviewed candidate image → Apply Update with rollback.

- **9A client.** The AeDebug crash handler MerlinCrash, MerlinClient.dll, the
  MerlinAI window, MerlinAI.cpl and MerlinSvc. Lab suite 22/22 under KVM UP,
  two-vCPU KVM and TCG (native build 06: `merlin-9a-up-08`, `-mp-02`,
  `-tcg-02`). Native build 08 (Security Center fix below): `merlin-9a-up-09`
  24/24, `-mp-03` 24/24, `-tcg-03` 24/24. The M9 baseline
  (`XP25-M9-Baseline.qcow2` `a3bde9b2…5e08`) passes the security `proof` 35/35
  under UP, MP and TCG (`tcg-01` kept: 32/35 under host load).
- **9B builder.** `MerlinAI-Builder` is a separate KVM guest (Ubuntu 24.04,
  nested KVM, read-only image disks, immutable baseline repository
  `c88f545de`). Per-installation workspaces, investigation, MinGW check,
  native NT build in a nested build VM, candidate overlay, update content.
  Self-test job `J-20261121-222239-cf27e5`: `fixed_verified`, tested after
  the fix under UP, MP and TCG. Two bring-up failures are kept on the builder.
- **9C/9D and Phase 12.** On `XP25-MerlinAI-Demo`: crash → Send to MerlinAI →
  Build an Update (`J-20261121-223005-f06e40`, ready in about 15 minutes,
  `fixed_verified`, 22 tests) → Review → Apply Update → the defect is gone
  and the user's document is intact → Roll Back → the defect is back. The
  demonstration found three deployment-agent defects. Each failed safely or
  was recovered by a journaled operator command; all were fixed and kept:
  - NoNewPrivileges broke FUSE, so the first apply was refused after shutdown;
  - the first rollback booted a read-only backing file, so the VM stayed off;
  - a state-file write race.

  It also found the Control Panel "Security Center" tile still opening Windows
  Security Center. Fixed in build 08 with the per-user "Hide specified Control
  Panel items" policy, and MerlinAI moved to Performance and Maintenance.
- **Not done.** No AI model was used: no provider key, so the offline
  rule-based investigator decided every job, and the model loops are tested
  only against mocks. The pipeline rebuilds only MerlinAI's own components.
  Build 08 passes 24/24 under UP, MP and TCG but is not packaged into an image or the builder baseline. Nothing was
  pushed.

[Record](merlinai-milestone9.md)

2026-11-21, Supermium replaces Internet Explorer in the XP25-Winlogon-Fix VM
(`xp25-modernization`; evidence `.work/supermium-vm-20261120/`). The VM's own disk
(`6dbd3f88…00f6`) got Supermium 150.0.7871.255 R2.01 (pinned package
`d9a06a6c…43b3`), XP25 Help for Start-menu Help, and a native User Accounts
applet. IE8, MSHTML, JScript, VBScript, `mshta` and Internet Options were then
unregistered and deleted, with their `dllcache` and language copies, at the next
boot (`build/ie_removal.py`, `browserctl delete-at-boot`/`unregister-file`).
WinINet, URLMon, Shdocvw, BrowseUI, IEFrame, IERtUtil and `ieproxy.dll` stay:
Explorer needs them. Install and verify runs (removal probe 27/27), then
`vm/package_vm_browser_image.py`: `image-02/XP25-Supermium-NoIE.qcow2`
`9e1e8f081b3ffc113aa4bf9f20e9b82097c681952c271b05fbf7a9e8f3e5b84d`. It has 295
installed files matching the media and all 36 removed files absent.

Tests on one-vCPU KVM overlays of that image:
- browser regression through a host gateway admitting any public HTTPS name:
  23/26 checks. DevTools 11/11, including `https://www.wikipedia.org/` over
  TLS 1.3, the certificate matrix, persistence, MSI, AI 55/0 + 7/0, and a
  Start-menu turn-off. The false checks are Remote Registry, disabled by the
  baseline, and the four `not_tested` cases;
- `proof` 34/35. The audit lists four USB drivers (`HidUsb`, `mouhid`,
  `usbhub`, `usbuhci`); the unchanged reference disk fails the same gate
  (`ref-proof-up-01`);
- screen-saver probe 10/10;
- switch oracle 9/9.

Kept failures:
- `image-01`: packaging interrupted;
- `img02-browser-up`: the DevTools fixture was not usable on a hardened image.
  The test media now grants the profile folder and opens the bridge port, and
  native build 04's shell probe checks either Internet policy;
- `img02-2acct-up-01`: 8/9, the oracle captured the gap before the dialog.

Host: a DHCP reservation `10.25.0.26`, the filter `xp25-browser-gateway`, and the
user service `xp25-browser-gateway` (`vm/browser_gateway.py --listen
10.25.0.1:3128 --allow-any-public`). The VM got the disk (old one kept as
`XP25-Winlogon-Fix.ie8.qcow2`), 1 GiB and the filter; `update.py compare`
reports nothing else changed. By screenshot in the VM: the Start-menu Internet
entry is Supermium, Wikipedia loads in it, `iexplore` is not found, logoff
returns to a painted dialog. Left at the logon dialog. Not done: two-vCPU and
TCG, `firewall`/`standard-user`/`ai-repeat`, lifecycle harness; no renderer
sandbox on NT 5.1; `0x842214` still open.
[Record](supermium-replaces-ie.md) · [VM](virt-manager-xp25-winlogon-fix.md#supermium-replaces-internet-explorer-2026-11-21)

2026-11-20, the XP25-Winlogon-Fix VM redeployed with R-0 and R-1
(`xp25-modernization` `16062930d`; evidence `.work/vm-redeploy-20261119/`). The VM
was turned off by the guest's own Turn Off. Its disk was frozen as a reference
(`a0cd3262…`), and the new `build/package_image.py` replaced four files offline,
each checked against its expected installed hash and its build collection:
- `winlogon.exe` `289abb03…` → `020eaf40…`;
- `win32k.sys` `b28afb2f…` → `f698e04d…`;
- `user32.dll` `a51976dd…` → `4cccacd3…`;
- `gdi32.dll` `09698075…` → `13e538d3…`.

The result is `XP25-R0-R1.qcow2`
(`c51832288b286bce510edccc2666581fa4a14e1d64c71b25cdecbbe94d49e6b7`). On that
exact image the switch oracle passed 9/9 and the screen-saver probe 10/10
(`image01-ss-up-04`). Three earlier screen-saver runs on it are kept as failed:
the guest behaved correctly, but Winlogon lines were lost from COM1 (roadmap
R-0b). The harness now turns the guest off normally and decides gates from serial
records merged with the guest's file logs. The VM runs a reflink copy; the
previous disk is kept as `XP25-Winlogon-Fix.289abb03.qcow2`. Only the domain
description changed, and no other domain, network, filter or running VM changed.
By screenshot: boot, logon and logoff with painted dialogs. The VM was left at
the logon dialog. [VM record](virt-manager-xp25-winlogon-fix.md#redeploy-with-r-0-and-r-1-2026-11-20)

2026-11-19, R-1: assessment of the source-built Microsoft components after 1106
(`xp25-modernization`; evidence `.work/r1-20261119/`). `build/bulletin_index.py`
indexed all 1,001 bulletins MS02-001…MS14-085. Windows XP candidates: 8 LSASS,
0 SCM, 1 Winsock (a false positive: `dnsapi`/`rasadhlp`), 36 win32k and 15
GDI/USER.

Located in our source and **fixed** (`components/cve/`), six defects:
- `win32k`: the GDI handle-table section handle left in every GUI process with
  `SECTION_ALL_ACCESS` (MS07-017, CVE-2006-5758 by description);
- `win32k`: unchecked animated-cursor sequence indexes and starting step;
- `win32k`: unchecked keyboard-layout NLS function index and type (MS10-073);
- `win32k`: an uninitialized path-record link on a failure path (MS13-053);
- `user32`: ANI chunk sizes, order and frame count, and wrapping file-map bounds
  (MS07-017, CVE-2007-0038);
- `gdi32`: WMF `SETABORTPROC` (MS06-001, CVE-2005-4560).

One candidate (`SEC_NO_CHANGE` on the view) was withdrawn: the section already
has it. Host ASan tests compile the real functions from both trees. The original
overflows, and the patched code rejects every malformed layout. The control
build reproduces the installed `win32k.sys`, `user32.dll` and `gdi32.dll` exactly
(0 other differing bytes). Patched build 02 differs only in the six patched
functions and relocated addresses.

Guest (8.2 image): on the shipped binaries a GUI process holds `SECTION_ALL_ACCESS`
handle `0x774` to the GDI table section. With the patched trio it holds none on
UP, MP and TCG; all 34 `.ani` and 150 `.cur` cursors load and draw, WMF and EMF
play, and `proof` passes 35/35 on UP, MP and TCG.

Suspected and not located (mechanisms never published): three LSASS local EoPs
(MS04-044, MS08-002, MS11-014) and most of win32k/GDI's bulletins, the largest
residual risk. `services.exe`: no finding (MS06-011 DACLs verified offline).
`ws2_32`: no finding in the reviewed paths. Kernel and CSRSS not assessed.
Not installed in any image. [Record](source-built-component-assessment.md)

2026-11-19, R-0: screen savers and the idle lock in the XP25 Winlogon
(`xp25-modernization`; evidence `.work/screensaver-20261119/`). **Implemented and
verified.** Winlogon now acts on USER's `LOGON_INPUT_TIMEOUT`. It starts the
configured saver with `STARTF_SCREENSAVER` on `WinSta0\Screen-saver`, with the
station switch-locked:
- at the logon desktop, `.DEFAULT`'s saver, as SYSTEM;
- in a session and on a locked station, the user's saver, as the user.

An open MSGINA dialog gets the WLX screen-saver notice first. A secure session
saver (`ScreenSaverIsSecure` and `WlxIsLockOk`) ends in a lock. Ctrl+Alt+Del
during a secure saver locks before the unlock dialog. Portable rules are in
`screensaver.c` (host test: 6,732 checks under ASan/UBSan). Native build
`ss-wl-build-02`: CL `/W4 /WX`, no warnings, `winlogon.exe`
`020eaf4047dfeae7ed7ebdab507d951766e715065917430c9d6bb41f600e0f2b`.

`vm/winlogon_screensaver_probe.py` (10 gates from Winlogon's and the probe's
serial records) passed on 1-vCPU KVM, 2-vCPU KVM and TCG. It covers:
- a non-secure saver back to the desktop;
- USER's notices stopping 0.25 s after the start;
- a secure saver locking, ended by a key and by Ctrl+Alt+Del;
- a saver on a station locked with Win+L;
- `logon.scr` interrupting the logon dialog after logoff.

Regression with this Winlogon on the 8.2 image:
- switch oracle 9/9;
- lifecycle harness pass on UP, MP and TCG;
- `proof` 35/35 on UP, MP and TCG;
- `standard-user` 12/12 on UP.

Kept failure: `runs/ss-up-01`. The guest behaved correctly; two gates failed on
the harness's reading of the records. XP25 guests now show the Windows XP logo
saver after 10 idle minutes, as stock XP does. Request 2 (monitor off) is not
tested. [Record](winlogon-screen-saver.md)

2026-11-19, the XP25-Winlogon-Fix VM moved to the Milestone 8.4 Winlogon
(`xp25-modernization`; evidence `.work/winlogon-vm-20261119/`). The VM's own
disk, shut down by the guest with its state kept, was frozen as a reference
(`355d8091…`). `build/winlogon_package_image.py` replaced only `winlogon.exe`
(`f24bba5b…` → `289abb03…`), giving `image-01/XP25-Winlogon-M84.qcow2`
(`471e1b068070915fbb334b77ef0ec307e3ff114ec81d1cc22f6deb74daf8d95a`). The
two-account oracle on that exact image **passed** on one-vCPU KVM: 9/9 switches
painted, accounts alternating, wrong password refused. The VM now runs a reflink
copy of the image. The previous disk is kept beside it, unchanged, as
`XP25-Winlogon-Fix.f24bba5b.qcow2`. Only the domain `<description>` changed. No
other domain, network, filter or running VM changed. By screenshot: boot to a
painted logon dialog, then two logon/logoff cycles, each back at a painted
dialog. The VM was left running at the logon dialog. The old Winlogon had grown
the VM's `native-winlogon.log` to 17.2 MB, 169,280 of its 169,919 lines being the
idle screen-saver notice. MP, TCG and lifecycle runs were not repeated on this
disk. [VM record](virt-manager-xp25-winlogon-fix.md#update-to-the-milestone-84-winlogon-2026-11-19)

2026-11-19, Milestone 8.4 — source audit, modernization and optimization
(`xp25-modernization`, from `a77550aa6`; there was no Milestone 8.3). Evidence
root `.work/modernization-20261118/` (`M`). **Repository inventoried, every
XP25 subsystem assessed, five verified improvements committed separately.**
`Source/` re-hashed unchanged (277,863 files, `9ff55c73…a151`); the accepted
8.1/8.2 images are unchanged.
**Audit.** `build/modernization_inventory.py` (378 tracked files outside
`Source/`, 8 native targets, dependency graph, complexity, API use,
duplicates), `build/static_analysis.py` (71 units through MinGW GCC
`-fanalyzer` + extra warnings, portable cores with host GCC, pyflakes:
120 diagnostics, all triaged). Sanitizer fuzzing of eight parser targets:
3 × 3,000,000 inputs per target, 0 reports; JSON parser 99.5% line coverage.
Manual review of the broker, IPC, policy and tools, the RoverAI watcher and
Explorer bar, ClippyAI's worker and Winlogon.
**Changes** (each native-built with `/W4 /WX`, checked, measured):
- `eff7915c3` RoverAI Explorer bar search thread holds its module (DLL could
  unload under it in Explorer; code-level, not reproduced).
- `d9daa5711` ClippyAI exit while an approval is open: 15.06–15.19 s hang,
  then state freed under the worker → 0.09–0.16 s, nothing freed under it
  (`clippyexit` probe, also under full page heap).
- `5400257ce` RoverAI reconcile with a cursor + inline case folding:
  byte-identical to the old index on 900 randomized rounds; rescan 4.2×
  faster on the host (1,848 → 436 ms), KVM rescan 2,687 → 2,125 ms, TCG full
  scan 46.0 → 39.2 s.
- `e4db3556b` `/GS` for the five AI binaries: 162 protected epilogues,
  initializer wired (`build/gs_check.py`), cookies initialized at run time 8/8.
- `5c690eb4c` Winlogon: the screen-saver notice USER repeats twice a second
  while idle (no screen saver ever starts) is no longer logged per notice:
  COM1 70/110 → 104/104 opens, log 23,520 → 0 bytes per idle minute. Found by
  measurement. Screen savers and idle lock remain unsupported (roadmap R-0).
**Regression** (overlays of the 8.2 image with AI build 17 and Winlogon
`289abb03…`): `proof` 35/35 UP/MP/TCG, `firewall` 27/27 UP/MP/TCG,
`ai-repeat` under host load 14/14 UP/MP, `standard-user` 12/12 UP/MP/TCG;
Winlogon lifecycle harness pass UP/MP/TCG; account-switch oracle 9/9. Host:
141 tests OK (12 skipped), session coordinator under ASan 913 checks 0
failures. Kept failures: `m84-ai-native-15` (C4054 cast),
`m84-rover-phases-up-01` (probe called `__stdcall` exports as `__cdecl`),
`m84-rover-phases-tcg-01` (COM1 lost to the Winlogon idle notice — the defect
fixed above), `m84-std-up-01` (two COM1 markers lost at logon),
`m84-std-tcg-01` (two unexplained resets after RasMan start, no dump; rerun
passed). Start-up timeline (new `serial-timeline.jsonl`): logon prompt by
12.1 s and logon → desktop within 4 s under KVM. **Not done:** no image was
repackaged; Winlogon, XP25Sec and XP25Audit without `/GS`; the 25 Microsoft
binaries built from source stay checked builds without `/GS`; not pushed.
[Audit](architecture-modernization-audit.md) ·
[static analysis](static-analysis-findings.md) ·
[optimization](optimization-opportunities.md) ·
[roadmap](modernization-roadmap.md)

2026-11-18, account-switching fix packaged and in virt-manager
(`xp25-winlogon-ui`): `build/winlogon_package_image.py` built the engineering
image `.work/winlogon-vm-20261118/image-01/XP25-Winlogon-Fix-8.2.qcow2`
(`fe633d1570f042b3cc8f869ad0fe1f6fabfc0e048ab57437b8d5c6e89f1ec173`). It is the
accepted 8.2 image `5a84781f…` with only `winlogon.exe` replaced offline
(`e3a9cdca…` → `f24bba5b…`, the build of commit `558cd3cda`). The two-account
oracle on that exact image, with nothing staged, **passed** on one-vCPU KVM: 9/9
switches painted, accounts alternating, wrong password refused
(`runs/image01-2acct-up-01`). The persistent `qemu:///system` VM
**XP25-Winlogon-Fix** runs a standalone reflink copy of it (MAC `:07`,
XP25-Isolated, gateway-only filter). By screenshot: logon, then two logoffs, each
back at a painted logon dialog. It was left running at the logon dialog. No
other domain, network, filter or running VM changed; the 8.1 and 8.2 accepted
images are unchanged. MP, TCG and lifecycle runs were not repeated on this image.
[VM record](virt-manager-xp25-winlogon-fix.md)

2026-11-17, XP25 Winlogon account-switching fix (`xp25-winlogon-ui`, from
`fb31686c0`): **root cause established and fixed; verified under one-vCPU KVM,
two-vCPU KVM and TCG.** Evidence `.work/winlogon-ui-20261116/` (`W16`).
After an account switch the logon dialog's user-name and password edits were
blank on every other switch, and they also ignored typing: a password typed into
them acted as dialog shortcuts and powered the guest off (`W16/runs/stock-2acct-up-01`).
**Cause:** win32k's `EndShutdown` empties the station's global atom table at
every logoff. comctl32 caches its subclass-property atom, so MSGINA's
subclassed logon edits lost their subclass data whenever the station
re-assigned `CC32SubclassInfo` a different atom (`0xC017` vs the cached
`0xC019`, alternating). comctl32 then resets them to `DefWindowProcW`. Trace
builds showed the blank edits' window procedure is `user32!DefWindowProcW`,
and that the cached/station atom mismatch matches the blank cycles exactly.
**Fix:** after the Winlogon's own `ExitWindowsEx(EWX_LOGOFF)`, call
`InitCommonControlsEx(ICC_WINLOGON_REINIT)`. This is comctl32's documented
Winlogon contract, and the original Winlogon's "Reset ComCtl32" notification
makes the same call. It is 23 lines in `components/winlogon` with an unchanged
import table. No repaint, sleep or other session change was needed. The
earlier "framebuffer"/desktop-presentation explanation is withdrawn.
**Verification** (build `63308b0f…`; the committed source rebuilt as
`f24bba5b…`, equal after link-metadata normalization and also run directly):
- Pixel oracle with two password accounts alternating through logoff and a
  refused wrong password: 9/9 (KVM UP), 9/9 (KVM MP), 5/5 (TCG), 9/9 (`fix02`).
  The stock Winlogon fails at the first switch.
- Winlogon lifecycle (18 gates incl. lock/unlock, Windows Security, Explorer
  recovery, logoff, relogon, isolated network 17/17): pass under KVM UP, KVM MP
  and TCG.
- Lock/unlock after the switch, desktop restart (guest `RESET`) and relogon,
  desktop Turn Off (guest `SHUTDOWN`, overlays frozen): pass under KVM UP,
  KVM MP and TCG.
- Host: 134 tests (15 skipped for private inputs absent in this worktree);
  session coordinator under ASan/UBSan, 913 checks, 0 failures.

Kept failures: `fix01-2acct-mp-01` (operator error: two vCPUs on the 8.1
uniprocessor HAL, `0x7E` before the Winlogon ran) and the oracle's
never-working PNG conversion (now records the PPMs). **Not done:** no packaged
image or virt-manager VM carries the fix yet (8.1 `501c7986…` and 8.2
`5a84781f…` still have `e3a9cdca…`). [Root cause and verification](winlogon-account-switch-paint.md)

2026-11-13, Milestone 8.2 — historical Windows XP CVE audit and source-level
remediation (`xp25-cve`, from Milestone 8.1 `a90f3fa80`): **all seven target
vulnerability groups mapped and classified
([audit](historical-cve-audit.md)); three confirmed source vulnerabilities fixed
and proven, one installed.** Evidence root `.work/cve82-20261112/` (`W82`).
**Installed fix — MS04-011 / CVE-2003-0533 (LSASS DsRole):** the image's
`lsasrv.dll` is the 1106 source-built binary, and its `DsRolepDebugDumpRoutine`
overflows a 1024-WCHAR stack buffer with a caller-supplied domain name logged
before any access check. Fixed (bounded `_vsnwprintf`; `DsRolepCheckPromoteAccess`
before logging), rebuilt, verified to differ from an unpatched control build only
in the three patched functions, and installed in the new image
`XP25-CVE-Hardened-8.2.qcow2` (SHA-256 `5a84781f3adee8861f8b7e3cd5b57ee11778e87a3b7683111ebf9e31ba80eada`), upgraded from the unchanged
Milestone 8.1 image. The full regression (Winlogon auth, Explorer/Luna,
ClippyAI/RoverAI 55 + 7, firewall, programs) and the MS04-011 guest checks pass on
the patched binary under one-vCPU KVM, two-vCPU KVM and TCG.
**Source-fixed, not installed (installed binary already a patched Service Pack 3
build):** MS08-067 / CVE-2008-4250 (`netapi32` `CanonicalizePathName` read
underflow, fixed and compiled in `netlib.lib`) and MS03-026 / CVE-2003-0352
(`rpcss` `GetMachineName` stack overflow, fixed and host-proven; native rebuild
proposed for 8.3). Each fix has a host test that AddressSanitizer catches on the
original and passes on the patched code (16 tests, `tests/test_cve.py`).
**Documented, deferred to 8.3:** CVE-2019-0708/BlueKeep (binary-only + RDP
disabled), MS17-010/EternalBlue (binary-only, unloadable, SMB disabled),
MS10-046 (installed `shell32` already patched), MS14-064 (no source, only a stub).
No existing baseline protection was weakened; the parent 8.1 image and `Source/`
are unchanged. [audit](historical-cve-audit.md) · [remediation](historical-cve-remediation.md)

2026-11-12, `XP25-Security-8.1` in virt-manager: a persistent `qemu:///system`
VM on a standalone reflink copy of the accepted 8.1 image (copy hashed
`501c7986…fda4`), lab hardware profile (1 vCPU, 512 MiB), `XP25-Isolated`
with XP25-AI's gateway-only filter. Observed by screenshot: boot, logon as
`XP25` with licensing admission, desktop. No other libvirt definition, the
running XP25-AI or the accepted image changed. Left running.
[record](virt-manager-xp25-security-81.md)

2026-11-13, Milestone 8.1 — security stabilization, firewall verification and final
acceptance (`xp25-security`): **`XP25-Security-Baseline-8.1.qcow2` (SHA-256
`501c79862d41824a2748c96f5b4715f22ba25443630cb1e3ff0c13674999fda4`), upgraded from the unchanged Milestone 8
image, passes the firewall, privilege, standard-user, AI and full proof suites
under one-vCPU KVM, two-vCPU KVM and TCG, and rollback on two-vCPU KVM. It is
not safe for hostile networks and does not have current-Windows security.**
Evidence root `.work/security81-20261112/` (`W81`).
**Firewall:** the Milestone 8 kernel export was retained (the image boots the
relinked kernel; `KeFlushQueuedDpcs` ordinal 526; no driver imports the kernel
by ordinal). New role `firewall` checks the service and IPNAT from inside, and
a test listener from the adjacent network in every state, on the sockets and in
the packet capture: blocked without an exception, reachable with the
administrator's exception, closed again after it (a UDP conversation state
lasts briefly and ends within 150 s), opened exactly by an administrator's
disable/stop and closed by enable/start, unprivileged `netsh`, `net stop`,
service, key, device and broker attempts refused, nothing answering at any
moment of a restart (`fw-up-03`/`fw-mp-01`/`fw-tcg-01`, 27 gates each).
**Found and fixed:** Power Users could stop the firewall, Security Center and
broker services (default DACL); every user could create scheduled-task files
(a contained process could escape through the Task Scheduler); NetBT's start-up
broadcasts let a neighbour reach UDP 137 during a restart and keep the
conversation (now a point-to-point node); the SYSTEM broker stopped the DNS
Client and Task Scheduler for ordinary users, served the browser's restricted
token, let its pipe name be taken over between clients (NT 5.1 has no
impersonation privilege), could be held by a silent client and logged under All
Users (AI build 13: caller checks, two-tier service lists, permanent
first-instance pipe, identification-level clients that verify the pipe owner,
bounded I/O, protected log); RoverAI's background indexer overwrote a fresh
re-index with an older listing (AI build 14). **AI stability:** the two
Milestone 8 failures were fixed sleeps after posted messages in the probe; it
now waits for ClippyAI to finish each step and records its duration
(minimize ≈0.3 s, settings OK ≤0.11 s under moderate load). Three rounds each
under moderate host load pass on UP and MP (`ai-load-up-01`/`-mp-01`, 14
gates). **Standard user:** logon, own profile and shell, Luna, files, ClippyAI,
RoverAI, broker, IE8, the programs and games installed with Windows, restart
and power-off all work without administrator rights (`std-up-08`/`std-mp-01`/
`std-tcg-01`, 12 gates each); recommended as the default desktop once a
pre-existing XP25 Winlogon defect is fixed: after a logoff the logon dialog's
fields do not paint, and the lab switched accounts with a restart instead. **Kernel review:** no
new kernel or HAL change; the relink is reproducible (equal after link time
stamps are masked) and changes only the export table and the placement of
about 50 functions. **Image:** `upgrade-up-02` (14 gates) on the Milestone 8
image, then `proof-up-01`/`proof-mp-01`/`proof-tcg-01` (35 gates each)
and `rollback-mp-01` (12 gates). Microsoft Hearts crashes when its opening
dialog is closed, on the unhardened base too (pre-existing). Storage: 337 duplicate screenshots deleted and 58 frozen run disks compressed in place (bytes unchanged); free space 49.06 → 90.31 GB on the shared volume.
Host tests: 114 OK (12 skipped), test_security.py 19. Earlier images, `XP25-AI` and `Source/` are unchanged.
[record](security-regression.md#milestone-81--stabilization-firewall-verification-and-final-acceptance) ·
[baseline](security-baseline.md) · [threat model](security-threat-model.md)

2026-11-12, Milestone 8 — operating-system security baseline and attack-surface
reduction (`xp25-security`): **A hardened standalone image,
`XP25-Security-Baseline.qcow2` (SHA-256
`6da7d04ed4f2f768d390be875228643648a7a36801e4bfe37854fdf8d7ee45d9`), is built from
the verified AI image plus the XP25 Winlogon and passes the complete security
and compatibility suites under one-vCPU KVM, two-vCPU KVM and TCG; rollback is
proven. It is not safe for hostile networks and does not have current-Windows
security.** Evidence root `.work/security-20261111/` (`W`); nothing pushed.
**Base:** the two verified lines were combined for the first time (AI image-05
`ec22f45b…` + Winlogon build 10 `e3a9cdca…`) and passed the established suites
before any change (`pre-up-02`: AI 55/0 + 7/0, all compatibility probes 0).
**Audit findings, all observed in recorded guests:** (1) Windows Firewall could
not start — `ipnat.sys` imports `KeFlushQueuedDpcs`, which the source-built
kernel did not export; TCP 135/139 and UDP 123/137 were reachable. (2) With
the firewall on, UDP 137 still answered 60 of 60 probes while the guest
broadcast NetBIOS queries (the firewall admits replies to the computer's own
broadcasts). (3) `system32\ue51sp3.dll` was writable by Everyone: any local
account could run code as SYSTEM. (4) Kernel, HAL, NTFS driver,
`XP25Broker.exe`, RoverAI COM registrations and `HKLM\SOFTWARE\XP25` were owned
by the administrator account, so a restricted process of that account (the
browser containment model) could rewrite them — 12 failed probe cases. (5) The
SYSTEM `XP25Broker` stopped the firewall for an ordinary account. (6)
`shutdown.exe`/`InitiateSystemShutdown` do not work under the XP25 Winlogon (no
`InitShutdown` interface) — recorded, not fixed.
**Implemented:** the kernel export list gains `KeFlushQueuedDpcs` (Microsoft's
routine, already in the source; one line, kernels relinked, exports
1,464 → 1,465); native `XP25Sec.exe` (enumerate/plan/apply/verify/rollback: 18
service rules, 54 registry settings, audit policy, 8 access-control rules, every
original recorded before it is changed) and `XP25Audit.exe` (read-only JSON
audit with deterministic rules and a reference snapshot), both `/W4 /WX` with
the NT toolchain; the broker policy refuses the firewall and the Security
Center (AI native build 11); a negative-test probe that runs as an ordinary
account and as a restricted token; a lab that scans the guest from the
adjacent network. **Result on the image:** 11 services newly disabled, 5 of
which had been running (39 → 34 running services); nothing answers from the network (1,113 TCP
ports filtered, 8 UDP services and 60 repeated name-service probes silent, no
ICMP echo); ordinary account 71/71, restricted token 73/73 and administrator
36/36 probe cases as expected; the audit finds no high-severity issue, detects
the deliberate changes of the drift test and reports the lab's own Startup
fixture as an addition to its reference snapshot; AI 55/0 + 7/0 and the established
compatibility suite pass, with Remote Registry proven after an administrator
re-enables it. **Matrix:** `harden-up-04`/`harden-mp-03`/`harden-tcg-02`
(34 gates each) on the combined base and `proof-up-02`/`proof-mp-02`/`proof-tcg-03`
(32 gates each) on fresh overlays of the image all pass; `image-install-02`
(11 gates) built the image; `rollback-up-02` (12 gates) restored all 97
recorded originals. **Kept failures:** `harden-up-01` (two defects found and
fixed), `harden-up-02` (one AI provider case failed while other guests ran),
`harden-tcg-01` (found the UDP 137 window), `proof-tcg-02` (one AI tray case
failed while other guests ran), the first image `1c55d9ea…` and its runs
(superseded), native builds `sec-native-01/-02` (`/W4` findings).
**Not addressed:** the 25 source-built core binaries have no post-2003 fixes,
no `/GS`, SafeSEH, DEP or ASLR; no driver signing; the daily account is an
administrator with a blank password; Windows File Protection is not hosted;
TLS 1.0 only. `XP25-AI` and every earlier image are untouched; `Source/` is
unchanged. Host tests: 12 new in `tests/test_security.py` plus the core test
program; the whole suite passes (107 tests, 12 skipped because their private inputs live in other worktrees).
[security baseline and inventory](security-baseline.md) ·
[threat model](security-threat-model.md) ·
[regression record](security-regression.md) ·
[audit and baseline interface](security-engine-interface.md)

2026-11-11, Milestone 7B Phase 2 — **correction and final MP coverage**
(`xp25-browser`): the two previously-open `rendered_ShellExecute_HTTP/_URL` checks are
**fixed and now PASS**, and a clean two-vCPU KVM regression through the HTTPS gateway
(run `b7reg4-mp`, evidence root `.work/browser-7b3-20261111/`, `X3`) shows **every
enumerated item green** — ShellExecute HTTP/HTML/HTM/URL all render, JavaScript,
multiple tabs, the full HTTPS cert matrix through the gateway (valid loads;
expired/wrong-host/self-signed correctly rejected), downloads, profile+appearance
persistence across restart, browser restart, the 62 AI cases (55/0 + 7/0), URL-policy
block and normal guest shutdown. **Root cause / fix:** the shell-association launch
path does not carry the CDP path's `--proxy-bypass-list`, so with the test-only system
proxy it sent the internal `http://xp25.test` fixture to the CONNECT-only gateway as a
plain request (correctly refused). The harness (`build/browser_test_media.py`) now
**adds** a managed Supermium proxy policy (`HKLM\SOFTWARE\Policies\Supermium`
`ProxyMode=fixed_servers`, `ProxyServer=10.25.0.1:3128`,
`ProxyBypassList=xp25.test;localhost;127.0.0.1;10.25.0.1`) that every launch path
honours; the Phase-1 WinINET settings are preserved unchanged (purely additive) and the
pinned ISO is byte-identical (`7ca80511…`). This is a guest routing fix only — **host
isolation is unchanged**: the clean run's gateway log shows **11 allows** (only the 4
approved cert hosts) and **79 denies** (70 `not_allowlisted` google/wikipedia/
update.googleapis phone-home + 9 non-CONNECT), with the shell fixtures reaching the
in-namespace server **directly** (render proof). The only non-green gate is
`full_regression_coverage` (the four unchanged `not_tested` probe cases — a documented
coverage gap, not a regression). **No remaining regression failures.** An intermittent
RoverAI-indexer / Clippy-tray **timing-race flakiness** in the bundled XP25-AI assistant
suite was observed under back-to-back host load (runs 1–3: 3/1/7 varying AI-case fails)
and **cleared under low load** (`b7reg4-mp`: AI 55/0) — pre-existing, environmental,
non-browser, not caused by the correction (the AI-suite bytes are identical to the prior
passing runs). All overlays frozen `0444`; `XP25-AI` and other VMs untouched; committed
locally, not pushed. Still experimental; **NOT** classified as safe for unrestricted
Internet browsing.
[secure Internet browsing — Phase 2 verification](browser-security-7b.md)

2026-11-10, Milestone 7B Phase 2 — network-security verification and browser
hardening (`xp25-browser`): **Every required network-bypass class is blocked with
host-observed evidence, the full practical browser regression passes through the
HTTPS gateway, containment is re-verified, the latest Supermium build offers no
`0x842214` fix, and disposable recovery holds — the browser stays experimental and
is NOT classified as safe for unrestricted Internet browsing.** Evidence root
`.work/browser-7b2-20261110/` (`X2`, zstd-compressed); nothing pushed.
**Task 1 (network isolation):** a new committed gateway bypass test
(`tests/test_browser_gateway.py`) drives the real gateway over its UNIX socket and
asserts its decision for every class — **11/11** (not-allowlisted resolvable+
unresolvable, direct-IP public/metadata/loopback, IPv6-literal, wrong-port,
non-CONNECT, CRLF, allowlisted-name→non-global rebind, and a live-TLS allow with the
real `example.com` cert reaching the client). A new namespace isolation probe
(`vm/network_isolation_probe.py`) runs inside the same `unshare` isolation and records
`connect(2)` errno for every forbidden egress — **12/12 with and without the nft
firewall** (public Internet, alternative DNS, host LAN, home router, libvirt/LXD/
docker bridges, cloud metadata, public IPv6 = `ENETUNREACH` no-route; gateway-down =
`ECONNREFUSED` fail-closed; control reachable); the namespace holds one route
(`10.25.0.0/24`), no IPv6. Blocks are distinguished from ordinary failures by errno.
**Task 2 (regression through the gateway, MP/two-vCPU, run `b7reg-mp`):** JavaScript,
multiple tabs, the full HTTPS cert matrix **through the gateway** (valid `example.com`
loads; expired/wrong-host/self-signed badssl each correctly rejected `ERR_CERT_*`),
downloads, profile+appearance persistence across restart, repeated navigation, browser
restart, the 62 AI cases, URL-policy block and normal guest shutdown **all PASS**. The
gateway log independently shows **12 allows** (only the 4 approved hosts) and **51
denies** (44 real Chromium phone-home `not_allowlisted` incl. google/wikipedia + 7
non-CONNECT). Two checks are **not** green and are reported as open, not passes:
`rendered_ShellExecute_HTTP/_URL` (the ShellExecute launch path lacks the proxy-bypass
the CDP path carries, so the test-only system proxy sends internal `http://xp25.test`
to the gateway as a non-CONNECT request, correctly refused — a harness artifact, not a
product/security defect; the launches themselves all exit 0), and
`full_regression_coverage` (the four long-standing `not_tested` probe cases).
**Task 3 (containment, run `b7cont2-01`):** 6 browser processes per probe (launcher +
association); **all 12 primary samples denied `system32`, SYSTEM-inject, admin-file and
admin-registry = error 5**, controls discriminate, **all 6 `chrome.exe` are
`job_member=1`** (no breakaway) — admin/SYSTEM boundary (SAFER + Job), **not** a
renderer sandbox; documented residual = own-profile writable. **Task 4 (`0x842214`):**
newest stable **v150-r2.02** is the **same Chromium `150.0.7871.255`**; its changelog
is unrelated and upstream still lists the XP process-failure fix as in progress — **no
supported correction**, not adopted, stays tracked/unpatched (no assertion disabled).
**Task 5 (recovery):** disposable overlay discard leaves the base `0444` and SHA
byte-identical; a fresh overlay cold-boots clean (**15/15** shell checks, `b7coldboot-01`);
gateway restart **9/9** (denies/allows correctly, socket removed + fail-closed while
down, policy identical, TLS preserved); isolation is namespace-local/deterministic; and
host-state before/after is identical (`XP25-AI` running, libvirt/LXD unchanged, no
global firewall, no sudo). All overlays frozen `0444`; other agents' VMs untouched;
committed locally, not pushed.
[secure Internet browsing — Phase 2 verification](browser-security-7b.md)

2026-10-28, Milestone 7B secure Internet access — Phase 1 host-enforced network
containment DEPLOYED and VERIFIED (`xp25-browser`): **Secure, controlled Internet
access for the disposable XP25 browser VM works end-to-end and every restriction is
verified independently from the host (packet capture + nftables drop counters +
gateway decision log), with no sudo and no global-firewall change.** Architecture:
the guest runs in a `unshare --user --map-root-user --net` namespace (no uplink, no
default route, `ip_forward=0`, no public DNS); its only egress is an in-namespace
proxy `10.25.0.1:3128` relaying over a UNIX socket to the host CONNECT gateway
(`vm/browser_gateway.py`), hardened to allow only allowlisted public HTTPS names on
443, reject literal-IP/metadata/private/loopback and non-global DNS results, validate
the connected peer (rebind guard), keep TLS end-to-end, and fail closed. Added a
namespace-local nftables default-deny ruleset with drop counters (`browser_network.py
--firewall`, threaded through `browser_lab.py`). Host gateway test: **8/8** (live
TLS to example.com allowed; all bypass classes denied). Disposable guest run on the
7A image (`XP25-Browser-Experimental.qcow2` `6cad84c6…`, MP/two-vCPU, throwaway
overlay): **positive** `https://example.com/` loaded via the gateway (2 allows to
global IP `104.20.23.154`, 264 proxy pkts, clean shutdown); **negative** — pcap shows
**0 packets** leave `10.25.0.0/24`, real Chromium phone-home (google/gvt1/googleapis)
denied at the gateway, nft dropped 23 guest off-service + 12 IPv6 packets. An earlier
run (`b7net-01`) caught and fixed my own too-strict DHCP rule — which incidentally
proved the firewall genuinely enforces. Acceptance 1–3, 6, 7 met and host-verified;
`XP25-AI` and other agents' VMs untouched. **Criterion 4 (browser-process containment)
re-verified PASS on the 7A image** (`b7cont-01`): all 6 browser processes (root + 2
renderer + 2 utility + gpu) denied system32/SYSTEM-inject/admin-file/registry (error
5); baseline process could, known-restricted could not — admin/SYSTEM boundary (SAFER
+ Job), not a renderer sandbox. **Secure-config regression matrix**: MP = OS+isolation
+positive HTTPS all PASS; UP = OS+isolation PASS, positive browser nav NOT demonstrated
(single-vCPU cold-start too slow, UI-bound >130s, proven on MP); TCG practical = OS
+15/15 shell checks+isolation PASS (browser nav impractical under emulation). Still
experimental/not Internet-safe: no NT 5.1 renderer sandbox, intermittent `0x842214`.
Not re-run this session: full DevTools functional regression over the gateway (PASS
prior `matrix-150-02`). Committed locally, not pushed.
[secure Internet browsing — architecture and evidence](browser-security-7b.md)

2026-10-28, Milestone 7A offline integration — MP stability + accepted-form image
produced (`xp25-browser`): **Two-vCPU stability now PASS and the offline image is
produced and cold-boot verified; the browser still carries the experimental
designation (intermittent 0x842214).** The earlier "two-vCPU blocked by host
contention" note was wrong and is corrected: the `fstab-mp-01/02/03` early-boot
halts were an operator base-image error — `--mode mp` (−smp 2) was run against the
**UP** image `ec22f45b`, whose uniprocessor HAL BSODs under two vCPUs (reproduced
with ~26 GB host RAM free in `fstab-mp-03`). On the correct **MP kernel/HAL base**
`582d551d` (the base `finstall150-01` and the passing `matrix-150-02` used),
**`fstab-mp-04` = 20/20 clean launch/navigate/close cycles** (`root_code=0`, 0
non-zero process exits across 157, **0** `0x842214`/CHECK/crash), 15/15 shell checks,
genuine guest shutdown. The offline image was then built one guest at a time:
fresh clean install (`offline-install-01`, MP base, clean media `prepared-150-05`,
`XP25_IMAGE_INSTALL_EXIT=0`, launcher rejects script/extra-arg/non-HTML = 87, clean
shutdown) → `package_browser_image.py` (**292 installed file hashes + installed.ok
re-verified**, convert/check/compare) → standalone **`XP25-Browser-Experimental.qcow2`**
(3,591,766,016 B, no backing file, SHA-256 `6cad84c6c39e056e24bb84165665e0c47bbf13ec1e433d0de43c3b37a63b101f`,
manifest `experimental_unaccepted`) → cold-boot (`offline-coldboot-01`, fresh overlay,
no reinstall) **15/15 shell cases, 0 failures**, clean guest shutdown — independence
proven. `0x842214` fired 0 times in this loop and cold boot but is unresolved, so the
image stays **experimental**, not Internet-safe/accepted (per the milestone). All
frozen bases read-only; other agents' VMs and the live `XP25-AI` untouched; committed
locally, not pushed (7A). [GPU investigation, stability and status](browser-offline-7a.md)

2026-10-27, Milestone 7A offline integration — GPU investigation + stability
(`xp25-browser`): **No GPU configuration avoids the intermittent 0x842214 CHECK;
single-vCPU stability is clean; the accepted offline image is NOT produced this
session (host memory). Milestone 7A unaccepted, browser stays experimental.** An
A/B (12 cycles each, XP25 KVM) showed `--disable-gpu` (default, still spawns a
gpu-process) hit 0x842214 zero times, while `--in-process-gpu` removed the
gpu-process but **relocated** the CHECK to utility/renderer children (14 hits);
both rendered 12/12 pages with clean root exits. So 0x842214 is in the field-trial
Section handle inheritance common to all child types, intermittent, sometimes
non-fatal (spare child) and sometimes fatal (root) — no GPU config avoids it.
Kept `--disable-gpu` software rendering (rejected `--in-process-gpu`); no assertion
suppressed, no handle faked, kernel unchanged. Single-vCPU KVM **20/20
launch/navigate/close cycles PASS** (0 failed, 20 JS receipts); two-vCPU 20-cycle
loop **NOT TESTED** (a ~26 GB non-browser VM saturated host RAM; MP full regression
passed earlier). Accepted offline `XP25-Supermium-Offline.qcow2` **NOT TESTED/NOT
PRODUCED** (needs install+package+cold-boot boots; memory pressure) — recipe +
experimental designation documented. Committed locally, not pushed (7A).
[GPU investigation, stability and status](browser-offline-7a.md)

2026-10-27, Milestone 7B security hardening (`xp25-browser`): **Renderer isolation
investigated and a verified process-tree containment architecture implemented;
Milestone 7B unaccepted.** Supermium compiles its per-renderer sandbox off on all
pre-Win10 Windows (`renderer_main.cc:249`; GDI/DirectWrite + Vista+ integrity-level
dependency), inside `chrome.dll` — not re-enablable from our layer. NT 5.1 offers no
integrity levels/AppContainer/Win32k-lockdown/UIPI, so XP25 contains the **whole
browser tree** from `XP25Browser.exe`: a SAFER Normal User restricted token (admin
deny-only, privileges = SeChangeNotify) plus a Job Object (active-process + memory
caps, no breakaway, clean teardown), inherited by every renderer/GPU/utility child.
Verified live (MP KVM): the tree is `member=1` in the job and is denied, with
`error 5`, admin file/registry writes, `%WINDIR%\system32` writes, and SYSTEM-process
injection — while pages still render. Residual risk documented (shared token; no
UIPI/integrity on NT 5.1), so Internet stays disabled by default. Phase 1
host-enforced egress = namespace-with-no-uplink + allowlist CONNECT gateway (no
passwordless root, so libvirt/nftables firewalling is out of reach — documented);
existing libvirt networks and XP25-AI untouched. Secure config (Phase 4): TLS on,
no `--no-sandbox`/`--remote-debugging-port` in the install, `URLBlocklist=*`,
profile isolated by the token. No check disabled, no API faked, no unavailable
mitigation claimed; `Source/` unchanged. Host tests 70, 10 skipped, no failures.
[Architecture and evidence](browser-security-7b.md)

2026-10-27, Milestone 7 stability + 0x842214 investigation (`xp25-browser`):
**On KVM the browser now passes the full functional regression; two defects are
characterized, one fixed and one open; Milestone 7 stays unaccepted.** Re-running
`vm/browser_matrix.py` on the frozen install base with disk headroom, **both
KVM single-vCPU and two-vCPU pass every browser check** — modern JavaScript, local
HTML, multiple tabs, the full HTTPS certificate matrix (valid + reject expired/
wrong-host/untrusted), download, the new default Internet-block policy
(`URLBlocklist=*` blocks lab subdomain and public site), **profile + appearance
persistence across restart** (previously failing), 55+7 AI cases, and normal guest
shutdown; the only non-pass is the honest `full_regression_coverage` marker (four
`not_tested` probe cases). This resolves the earlier DevTools WebSocket timeout as
**host storage contention, not a browser defect**. TCG still renders shell + all
five ShellExecute types but its CDP calls exceed 45 s under single-thread
emulation; the timeout is now configurable (`XP25_CDP_TIMEOUT`, raised to 240 s for
TCG) and re-run in `matrix-150-03`. The `0x842214` CHECK was investigated: it is
`TakeHandleOfType("Section")` in the gpu-process parsing its inherited
`--field-trial-handle` (minidump: value 1836 is a `File`, not the Section); a native
`browser_inherit` probe shows progwrp's handle-list inheritance preserves a listed
Section's value/type on both XP25 and stock SP3 (so not a basic inheritance bug or
XP25-specific), and it reproduces on stock SP3 — a browser gpu-process
handle-lifetime defect with no safe compat-layer fix (can't patch chrome.dll or
disable the CHECK); documented, not forced. No CHECK removed, no API faked, no
sandbox weakened, `Source/` unchanged. Host: 67 tests, 10 skips, no failures.
[Evidence](browser-stability-security.md)

2026-10-27, Milestone 7 watcher fix + containment (`xp25-browser`):
**The first captured crash is fixed and the browser now runs reduced-privilege,
but Milestone 7 is still unaccepted and no new image is produced.** The directory
watcher CHECK (`chrome.dll` RVA `0x77b96f8`, error 995 in
`file_path_watcher_win.cc:357`) is an NT 5.1 issuing-thread cancellation
difference inside Supermium's own `pwrp_k32.dll`. A provenance-pinned proxy
(`components/browser/xp25_pwrp.c` + generated `pwrp_k32.def`, all 1703 exports
name/ordinal/forwarder-equal to the pinned original, which is kept as
`pwrp_k32_sm.dll`) re-issues the IOCP directory watch from one persistent thread.
A native `browser_watch` probe reports `failures=0` on XP25 KVM and the SP3
control (32/32 concurrent exited-issuer watches complete; event/routine/error
parity with `kernel32`), and an A/B test shows the CHECK firing only in
original-wrapper blocks (2 vs 0 on XP25). XP25 entry points now launch `chrome.exe`
with a SAFER Normal User token through `XP25Browser.exe`; a live probe shows the
browser root and children denied admin-only file/registry writes (error 5), and
the image blocks Internet browsing by default (`URLBlocklist=*`). Shell
integration and reduced-token rendering of HTTP/HTML/HTM/URL/HTTPS pass under
KVM-UP/KVM-MP/TCG. Still open and not faked: a separate `0x842214`
shared-memory handle-type CHECK, residual hangs/restart stability, and the
DevTools deep-regression matrix (its WebSocket timed out under ~98%-full-disk
contention; frozen as failures). No CHECK removed, no API faked, no sandbox
weakened, no IE DLL deleted, `Source/` unchanged. Host: 64 tests, 10 skips, no
failures. [Evidence](browser-stability-security.md)

2026-10-26, Milestone 7 stability/security follow-up (`xp25-browser`):
**Acceptance fails; Supermium 144 and 150 are unsuitable for unrestricted
Internet access on this NT 5.1 configuration.** An actual 150 shutdown crash
on original SP3 and the same watcher assertion on XP25 identify a CHECK that
rejects cancellation error 995. A native issuing-thread-exit test reproduces
that legitimate NT API result. No fake-success API or security guard removal
is applied. Matched short debug runs can pass, while unmonitored 144 MP exits
abnormally and the 150 TCG close times out. Active-renderer trace/token tests
on SP3 and XP25 fail protected file/registry boundaries; official 144 source
skips renderer lockdown before Windows 10. A native Win32 desktop Help viewer
and reversible Explorer resource integration are implemented, built with the
original NT toolchain and tested on KVM/TCG; legacy Help recovery is rehearsed.
Shared IE compatibility DLLs remain. No new accepted image is produced.
[Detailed evidence and remaining work](browser-stability-security.md)

2026-11-11, XP25-AI and the XP25 gateway (branch `xp25-ai`): **ClippyAI in the
running XP25-AI VM reaches OpenAI through the XP25 gateway on the host.
*Test connection* returned "Connected. The model replied: READY"
(`gpt-4.1-mini`, Responses API). This is the first real OpenAI call from an
XP25 guest.**

- **Cause of the failure.** The VM had no NIC after 2026-10-26, so ClippyAI
  reported `connect_failed`. The gateway was listening, on a bridge with nothing attached.
- **VM.** An RTL8139 was hot-plugged and persisted, with the same MAC and PCI
  slot as before. XP took it without a wizard and leased `10.25.0.13`.
- **Filter.** The NIC carries a new libvirt filter, `xp25-gateway-only`. Its
  layer-2 rules allow DHCP, plus DNS, ICMP and TCP 8443 to `10.25.0.1`, and
  drop everything else.
  - It references no guest address.
  - A/B check: the host reached the guest's TCP 139 with the filter removed
    and timed out with it restored.
- **Gateway.** New options `--api-key-file`, `--freebind` (bind the bridge
  address before it exists) and `--log -` (journal).
- **Service.** `xp25-gateway.service` and its installer: a dynamic user,
  root-only credentials, restart forever, exposure 1.5. It was tested as a
  user-mode unit against the test double; TLS to `api.openai.com` works under
  its seccomp settings.
  - **Not installed: it needs root.** The gateway still runs as the process
    started by hand.
- 65 host tests pass, 7 skipped for private inputs.
- Open:
  - installing the service;
  - an OpenAI usage limit, because Guacamole users can spend the key;
  - the `xp25.test` endpoint is untested from the guest;
  - XP25-Winlogon has no filter.
- [Record](xp25-ai-gateway.md)

2026-10-26, XP25-AI remote access (branch `xp25-ai`): **the rebuilt XP25-AI VM
is usable from a browser through Mise En Abyme's existing Guacamole, by any
verified Newbie user, one at a time; a live end-to-end test passed.**

- **VM.** XP25-AI was rebuilt on a fresh overlay of the accepted image-05
  (`ec22f45b…`, unchanged) with the QuoolAI configuration: 11/11 offline gates.
  - The network adapter is removed.
  - VNC is on a fixed loopback port with a password.
  - A USB tablet gives absolute pointing.
  - Autostart is enabled.
  - The previous overlay is kept.
- **MEA.** Guacamole there is MEA's embedded backend: its UI is not public, and
  its lifecycle extension admits only MEA desktop leases. A "shared desktop"
  feature was therefore added to MEA (one seat, normal lease rules, outside the
  EC2 cap). It was built on the live release once that was pushed, tested on
  PostgreSQL 17.6 and deployed.
- **Tunnel.** A t4g.nano relay EC2 in the MEA VPC accepts VNC only from the
  Guacamole task. The home host keeps an SSH reverse tunnel to it, carried over
  SSM Session Manager. No inbound ports are open anywhere.
- **Verified.**
  - The public site to XP25-AI: mouse, keyboard, disconnect and reconnect into
    the same session, the single seat, release and the second user. guacd's own
    logs show it.
  - The tunnel key cannot open a shell, a TTY, another listen address or a
    local forward.
- Not done: MFA for MEA sign-in (MEA has none).
- [Record](xp25-ai-remote-access.md), [operations](../remote-access/README.md)

### Earlier browser integration checkpoint

2026-10-25/26, Milestone 7 (branch `xp25-browser`): **Supermium integration is
implemented and preliminary XP25 browser/HTTPS tests pass; final acceptance is
in progress.** Official x86 150.0.7871.255 R2.01 is hash-pinned. The native NT
compiler builds the shell adapter and probes. Thirteen registration/shortcut
checks pass, along with local HTML, modern JavaScript, tabs, downloads, TLS 1.3
and rejection of expired, wrong-hostname and untrusted certificates in an
isolated guest. Software rendering addresses the unverified VGA/D3D path.
The browser internally disables its sandbox on this NT 5.1 configuration;
security isolation is not established. IE compatibility libraries are retained,
with a private static/runtime audit. Corrected HTTP/HTML/HTM/URL shell launches render the intended pages. All 24
registry rollback scopes and 12 shortcut paths round-trip. A hash-verified
standalone experimental QCOW2 is generated and independently boots. Its normal
restart test still fails JavaScript completion. Full KVM/TCG acceptance is blocked by browser crashes/timeouts.
Help and Support loads MSHTML/JScript at runtime; those dependencies remain. Previous images and registered
VMs remain outside this experiment. [Evidence and limits](browser-modernization.md)

2026-10-25, interactive VM configuration (branch `xp25-ai`): **XP25-Winlogon and
XP25-AI run at the same time, each with its own address and name, and System
Properties shows QuoolAI with the full "Windows XP 25th Anniversary Edition".**

- **System Properties.** The reviewed `sysdm.cpl` branding step widens the
  General page's Computer lines from 110 to 124 DLU and the page from 256 to
  270 DLU. No control moves, and the other five branded files are unchanged.
  - Installed offline on both VMs.
  - The `oem` probe checks text fit, overlaps, all seven tabs and fit at
    96/120/144 DPI; all 19 cases pass on both.
- **XP25-AI branding.** Same OEM file, Help and Support copy and backups as XP25-Winlogon.
- **DHCP.** The single-address dynamic range let dnsmasq hold only one lease
  ("no leases left"). A second range, `.20`–`.29`, was added with a live and
  persistent `net-update`, which restarted only that network's dnsmasq.
  - The VMs hold `10.25.0.12` and `10.25.0.13`, ping each other, see each
    other's NetBIOS names, and cannot reach outside addresses.
- **Computer names.** `XP25-WINLOGON` and `XP25-AI`, set with `SetComputerNameExA`.
  - WMI rename fails on the Winlogon image (`0x80041004`).
  - The independent Winlogon does not copy `NV Hostname` to `Hostname` at
    startup, as the original does. The active value is set directly instead.
- **Preserved and verified.** Frozen images, other domains, xp25-sp3,
  activation data, the 22 Winlogon components and the AI binaries are unchanged.
  Each VM passes 16 offline gates.
- **Rehearsals.** All of this was rehearsed on disposable overlays. One
  rehearsal had an unexplained restart that did not recur and is kept with
  `failure.json`.
- [Configuration record](xp25-vm-configuration.md)

The previous entry follows.

2026-10-25, interactive VMs (branch `xp25-ai`): **XP25-Winlogon now carries the
QuoolAI OEM branding, and a disposable XP25-AI VM is running in virt-manager.**

- **XP25-Winlogon.** The third-party `OEMINFO.INI` (`a1052310…`) was
  replaced offline on the VM's own writable disk with `[General]
  Manufacturer=QuoolAI / Model=Windows XP 25th Anniversary Edition`
  (`7760193a…`). Before that, a guest-requested shutdown was confirmed and the
  backups were made in the guest and on the host. There was no OEM logo.
  - Help and Support's copy of the values (`HelpSvc\OEMInfo`) was updated with `reg.exe`.
  - The new `oem` probe passes 15 of 16 cases. The 22 XP25 components, the branding
    and licensing files, and every other System Properties text are unchanged.
  - The model line is clipped to "Windows XP 25th Anniversary": 179 px of text in a
    165 px field. Fitting it needs either a shorter value or a wider line in
    XP25's branded `sysdm.cpl`, so it was left as specified.
  - The whole procedure, including restore, was rehearsed first on a disposable overlay.
  - [OEM record](xp25-winlogon-oem-branding.md)
- **XP25-AI.** A new libvirt domain whose disk is an overlay on the verified AI
  image-05 (`ec22f45b…`). It auto-logs on to the desktop (screenshot evidence
  only). Other domains, xp25-sp3, the default network and image-05 are unchanged;
  `XP25-Isolated` gained one reservation, `.13`.
  - The single-address DHCP range lets only one of these VMs hold a lease at a
    time, so XP25-AI has no IP while XP25-Winlogon runs.
  - [VM record](virt-manager-xp25-ai.md)

The Milestone 6 entry follows.

2026-10-25, Milestone 6 (branch `xp25-ai`): **ClippyAI, RoverAI and the shared
XP25 agent runtime pass guest acceptance under KVM (1 and 2 vCPUs) and TCG,
and the experimental QCOW2 is verified.** Native `/W4 /WX` build 10 passes
62/62 guest cases in each mode on the accepted engineering image (original
Winlogon, native Explorer and UserEnv): desktop, Explorer Search redirect,
RoverAI index/watcher/search, ClippyAI tools, approvals and troubleshooting
workflow, and OpenAI Responses requests through the authenticated gateway to a
test double. The full established regression suite exits 0 and every run ends
with a guest-requested shutdown. `XP25-AI-Engineering.qcow2` (SHA-256
`ec22f45b67af19f584eb6ca0a286e943731298543aa1b910eab6ff42674bee2a`) boots
independently and passes the same 62 cases. Guest runs of builds 04–08 found
and fixed: user-scope DPAPI error 1783 on the engineering images (keys now go
to Credential Manager), share consent asked for earlier offline results, two
index-store races including a stale overwrite by the background indexer, and
a runaway-process rule that missed single-threaded loops on multiprocessors.
No real OpenAI call was made (no key or uplink in the isolated lab).
[Architecture, security model, evidence, failures and limits](xp25-ai-clippyai-roverai.md)

2026-10-25: **`XP25-Winlogon` is registered in system libvirt for interactive
virt-manager use, running the independent Winlogon.** Its disk is a full,
unshared byte copy of `XP25-Winlogon-Engineering.qcow2` (SHA-256
`0df7fc05…c51c`). Before boot, its hash and `qemu-img compare` matched the
source, and it has no backing file. The VM uses the verified one-vCPU
qemu32/512 MiB/i440fx/IDE/VGA/RTL8139 KVM profile, a new UUID, MAC
`52:54:00:25:00:04` and a `.12` reservation on `XP25-Isolated`. A serial-gated
boot was observed through `core_ready`, the MSGINA logon dialog, a wrong-password
rejection, `XP25` logon, `licdll` admission and the Explorer identity check. It
also recorded Luna, the Start menu, the taskbar, the desktop, folder navigation,
Notepad, 26 passing probe observations, isolated DHCP/DNS and a guest-requested
shutdown. All 22 verified guest components are unchanged afterwards. The source
image, the remaining existing domains and the running `xp25-sp3` are preserved.
The VM is left running at the logon screen with its console open, and autostart
is disabled. During registration, the virt-manager Delete wizard removed
`XP25-Desktop` and its disk (04:28–04:29 local). This registration did not cause
that change; it is recorded in the evidence.
[Configuration, evidence and limits](virt-manager-xp25-winlogon.md)

The following entry describes the Winlogon checkpoint this branch is based on.

2026-10-25, Winlogon desktop and session continuation from `67de708ed`:
**the independent NT 5.1 Winlogon now starts the original Explorer with Luna
and runs the session lifecycle.** Licensing admission is decided by the installed
`licdll.dll` COMLicenseAgent using SP3 Setup's own `Activationrequired` sequence
(`Initialize(0xC475,1,NULL)`, status 0, `WPALeft == INT_MAX`); its ABI is
re-verified against the DLL's type library at runtime and nothing is forced.
Guest debugging found and fixed missing Winlogon duties: permanent font load
(userinit otherwise blocks in `win32k`), `WlxWin31Migrate`, logoff process-exit
wait, per-user system parameters, `Win+L`/`Ctrl+Shift+Esc`, status-message
removal, the MSGINA theme handoff and crash-recovery identity races.

Final native build 10, SHA-256
`e3a9cdca26ab7af5ae5b225d647c94be0dc34aa4f7428e025ddf3b3c3becdf93`, passes 18
gates (authentication, admission, Explorer identity, four regression probes with
Luna active, lock/unlock, Task Manager, Windows Security, Explorer crash
recovery, logoff with no remaining user processes, re-logon, 17-case isolated
network probe) and a guest-requested shutdown under single-vCPU KVM and
two-vCPU KVM and TCG, plus a desktop restart cycle. A standalone engineering
image with only this Winlogon (`XP25-Winlogon-Engineering.qcow2`, SHA-256
`0df7fc05b0b965941f4c488894ce200adcd44d91acf4bf28f93f7a445d30c51c`) passes the same
18 gates in an independent boot proof. Source, reference images and user VMs are
unchanged. Known gaps: Terminal
Services session state (`qwinsta` shows `Conn`, no user), unthemed logon desktop
and post-logoff GINA edits that accept input but do not paint, no Welcome
screen, Fast User Switching, event sounds or Group Policy processing. Build 04
failed the native compiler (C4701) and is retained; all 41 host tests pass.
[Licensing evidence, duties, builds, matrix and gaps](winlogon-desktop-session.md)

The following earlier entries describe their respective historical inputs.

2026-10-24, policy/session continuation from `8e4bdba7c`: **real NT 5.1
activation-key protection initialization now runs; licensing admission remains
blocked.** The supplied linked kernel contains the service in prebuilt
`systime.obj`; three original-host calls establish its two-output ABI. The new
Winlogon calls that real service and preserves failures. A typed, fail-closed
policy interface isolates the remaining unavailable activation/OEM/initialization
decision. No WMI observation or test double authorizes production admission.

The working profile/environment code now uses a shared session coordinator,
with explicit doubles confined to a separate test executable and a production
compile guard. All 40 host tests pass; 31 session scenarios / 528 assertions
also pass under sanitizers and in an authenticated original-host XP25 process.
That control passes actual token/profile/environment, file/HKCU, source
Explorer/Luna/Start/folder, networking and service checks, then normal shutdown.

A freshly compiled native `/W4 /WX` Winlogon, SHA-256
`120a9ddebcf610a060a8aac6d42ee01f9308e1deb8b34560f26e8d230b7030d1`,
boots in disposable verified-engineering UP KVM, MP KVM and TCG overlays. All
three authenticate, validate the SID hive/environment and clean up on policy
error 120; live resource readback confirms cleanup. Signed-out GINA power-off
passes under UP KVM, MP KVM and TCG; GINA restart under MP returns to MSGINA.
These limited power results do not establish desktop logoff or full lifecycle.

**Custom-Winlogon Explorer/Luna remains unaccepted.** Post-shell security,
lock/unlock/logoff, shell crash recovery and the full replacement regression
matrix remain incomplete. No accepted image is generated; Source, recovery
executables, prior images and persistent user VM definitions are preserved.
[Policy findings, code, native test/build hashes and exact limitations](winlogon-policy-session-contract.md)

2026-10-24, fresh Winlogon runtime verification: **the exact latest input
failed the native compiler** (`WlSessionActive` undefined; zero-key branch leaves
`read_stored_key` unused under `/W4 /WX`). Both failures are retained. A corrected
fresh native build links successfully, restores real SYSKEY handling, preserves
the guarded GINA shell implementation and fixes environment ownership and false
success paths. No older Winlogon binary is used.

A new single-vCPU KVM overlay of the hash-verified latest standalone engineering
image installs only that new executable. Actual LSA wrong-password failures and
successful status/substatus 0/0, token SID/LUID/type/session, correct profile hive
and environment, two initialization/cleanup cycles and live cleared ownership
are recorded. The matching native PDB resolves the admission call stack.
**Shell admission remains blocked by the implementation gap in product-activation
orchestration (`wl_session_policy`, error 120), not an activation-server error.**
GINA shell activation, Explorer/Luna and full desktop/lifecycle acceptance are
not reached; MP/TCG are not run for this revision. No new engineering image is
made. All 38 host checks pass and Source/reference images/user VMs are preserved.
[Exact-source build failures, fresh binary hash and actual guest evidence](winlogon-runtime-verification.md)

2026-10-24, Milestone 5 continued: **GINA environment merge and recoverable
pre-shell initialization failure now work in the native replacement.** Two
real authentication/profile/environment/cleanup cycles pass in disposable
single-vCPU KVM, two-vCPU KVM and TCG overlays. A read-only capture confirms
matching Winlogon/kernel checksums and cleared token/profile/environment/GINA
ownership. CSC's machine-lifetime Startup worker is retained instead of being
joined during user rollback; the first failed matrix and diagnosis are saved.
The native `/W4 /WX` build and all 38 host checks pass, including 24 environment
cases and a sanitizer run. The incoming forced-success/zero-SYSKEY edits were
saved privately and restored to the committed checks before building.

**Desktop acceptance remains blocked at `activation_policy_contract_unresolved`
(error 120).** Original licensing orchestration is still unavailable. GINA
shell activation, userinit/Explorer/Luna, full lock/logoff/power and replacement
security/application/network/service acceptance remain incomplete. No new
standalone image is produced; prior verified images and user VMs are preserved.
[Exact changes, native hashes, failures, coverage and reproduction](winlogon-session-recovery.md)

2026-10-24: [Winlogon licensing/activation investigation](winlogon-activation-investigation.md)
records the absent original orchestration source and unresolved COM, OEM,
kernel, registry-state and shell-admission contracts. No licensing state or
activation check was changed, removed or forced to succeed; activation
compatibility remains unresolved.

2026-10-24, Milestone 5 continuation: **native Winlogon now prepares and cleans
up an authenticated local user's profile.** New code loads UserEnv's profile,
checks its actual hive against the token SID, builds and validates the user
environment and releases both resources before token closure on rejected
startup. Fresh-account profile creation is demonstrated in one-vCPU KVM,
two-vCPU KVM and TCG disposable boot replacements. The actual SP3 NONAME profile
manager ordinal is corrected after recording a genuine error-127 failure.
Thirty-eight host checks pass, including thirteen environment parsing cases.

The guest still stops at `activation_policy_contract_unresolved`, error 120,
before GINA shell activation, userinit or Explorer. Activation enforcement has
not been removed or made to return fabricated success. Licensing-preserving
orchestration, GPO/GINA environment integration and the full desktop/session
lifecycle remain incomplete. There is no accepted replacement desktop or new
engineering image. The original-host fixture control passes two full suites
and normal shutdown; reference sources/images and user VMs are preserved.
[Profile-stage implementation and evidence](native-winlogon.md)

2026-10-24, Milestone 5: **independent Winlogon initialization and console
authentication implemented; replacement desktop not accepted.** New native C
builds successfully with the existing NT toolchain. Disposable single-vCPU KVM,
two-vCPU KVM and TCG guests register the real USER/CSRSS logon process, create
secure desktops, complete LSASS's actual stored startup-key exchange, wait for
SAM, register trusted LSA, negotiate original MSGINA 1.4 and invoke Startup
notifications. Wrong passwords are rejected, SAS interruption returns without
launching a shell, and valid existing credentials pass GINA and primary-token,
LUID, session and logon-SID validation. Separate KVM/TCG debugger captures show
real LSA success. These are authentication-core results, not completed logins.

The precise next boundary is `session.c:wl_session_start`, error 120 before
profile/shell activation. Original Winlogon's integrated WPA/OEMBIOS/mutex and
activation-key orchestration remains unaccounted for; no licensing check or
activation result is bypassed. Profile/policy/environment, Explorer/Luna,
lock/logoff/power lifecycle, hostile-client security tests and full replacement
regressions remain incomplete. No replacement standalone image was generated.
The previous verified engineering image remains current. Recovery to the exact
original host passes two complete existing suites and normal guest shutdown.
All 277,863 source files remain hash-identical; 37 host checks pass.
[Implementation, failures, recovery and reproduction](native-winlogon.md)

2026-10-24: **original Explorer and UserEnv pass independently and together**
under one-vCPU KVM, two-vCPU KVM and TCG. Explorer's first exception identifies
a wrong SP1 private SHLWAPI call; one source call-site fix uses the installed
SP3 descriptor provider. UserEnv's fatal Winlogon failure is a demonstrated
stack imbalance from four misbound private ordinals, corrected without changing
original implementation bytes or Winlogon/security checks. The earlier
0x0100ced1 exception is also handled in a working SP3 control and is not suppressed.
Both components are rebuilt in disposable native Windows guests. All nine
integration runs pass full regression, interactive session, live-component,
fresh-profile and normal-shutdown gates. Three missing UserEnv implementations
still forward to unchanged original SP3 code.
A new standalone 32-GiB engineering QCOW2 passes sector comparison and a separate
KVM cold boot with both full suites, lock/unlock, Notepad readback and confirmed
guest shutdown. Previous images, all source files and user VM definitions are
preserved. Thirty-five host checks pass. A clean installation ISO and complete
independent reconstruction remain separate milestones.
[Debugging, hashes, matrix, recovery and reproduction](native-explorer-userenv.md)

2026-10-23: **original Regsvc and MSGINA pass individual integration.** Each is
added alone on a frozen verified parent and passes KVM, two-vCPU KVM and TCG,
including live module identity, real Winreg RPC lifecycle/negative checks,
authentication failure/success, lock/unlock, Explorer/Luna, legacy/installer
fixtures, networking and fresh service/guest shutdown. Original recovery copies
and captured NT 5.1/x86/2600/SP3/product/licensing identity are preserved.

Original Explorer now compiles after generating original BrowseUI/Shdocvw import
libraries and building its original support libraries. Shell startup crashes in
its disposable integration test; it is not promoted. A deterministic UserEnv
adapter pins the full SP3 ordinal map and delegates three unavailable bodies to
unchanged original SP3 UserEnv. All fifteen process-only export/profile checks
pass, but Winlogon boot integration fails with `c0000005`/STOP `c000021a` in the
three configurations. The working installed UserEnv and Explorer remain active.
No Winlogon/security/licensing workaround is introduced. The Winlogon investigation
documents missing source, host contracts and implementation acceptance stages.

A reproducible private preinstalled engineering disk packages the accepted
SCM/SMSS/Regsvc/MSGINA desktop with its prior kernel, networking and branding.
It is not a clean Windows Setup ISO; authorized media/license provenance remains
pending, and no licensed-distribution or source-completeness claim is made.
Thirty-three host checks pass. [Evidence, failures, recovery and reproduction](native-component-extensions.md)

2026-10-23: **`XP25-Anniversary` is registered for interactive virt-manager use.**
Its independent, sector-verified disk copies the newest frozen branded desktop,
`brand-final-tcg-01` (2026-10-24 00:00:23 UTC). KVM uses its original one-vCPU
qemu32/512 MiB/i440fx/IDE/VGA/RTL8139 profile and original UP kernel/HAL. A unique
MAC and `.11` DHCP reservation avoid sharing `XP25-Desktop`'s MAC/IP; guest
files and registry/boot settings are not patched. Desktop, native-kernel live
checksum, all established probes, branding/installer fixtures, networking and
normal shutdown pass. Sixteen critical files, captured identity values, source
chain hashes and existing guests are preserved. The VM is shut off with
autostart disabled; its loopback VNC console is ready for the user to start.
[Configuration and evidence](virt-manager-xp25-anniversary.md)

2026-10-23: **XP25 visible branding passes the recorded guest matrix.** System
Properties, About Windows, graphical login and the Start menu carry XP25 names
on separate disposable overlays. Display strings are configurable and en-US
only; NT 5.1/x86/build 2600/SP3, product type, API reporting, registry ProductName
and captured licensing identity remain unchanged. Luna, original SCM/SMSS and
all established regressions pass under one-vCPU KVM, two-vCPU KVM and TCG, with
Calculator, Notepad, Win32/MSI fixture installers, reauthentication, networking
and normal shutdown. Original UI recovery copies and offline restore evidence
are retained. Source/reference hashes and existing libvirt guests are preserved.
Twenty-eight host checks pass. This is resource branding of installed UI
binaries, not additional original-source component reconstruction or a general
compatibility claim. [Audit, limitations, evidence and recovery](branding.md)

2026-10-23, Milestone 3: **original SCM reconstruction passes.** Native
`services.exe` replaces SP3 SCM in disposable KVM, two-vCPU KVM and TCG guests.
All established probes, fourteen real service-management observations, live SCM
image identification, interactive logoff/login, Notepad and guest shutdown pass.
A running fixture receives `SERVICE_CONTROL_SHUTDOWN`; the original SCM remains
in host and guest recovery copies. Independent native rebuilds succeed without
an SCM implementation patch. [Evidence and reproduction](native-components-milestone.md)

Original SMSS was then integrated alone on the frozen SCM checkpoints and passes
the same three configurations. At that checkpoint Regsvc, Msgina and UserEnv
were unintegrated candidates, and Explorer's private libraries were unresolved;
the extension checkpoint above supersedes those statuses.
The new full source inventory retains the original 277,863-file SHA-256 manifest.
Winlogon and two executive C sources remain absent; full OS reconstruction and
source completeness are not established. `XP25-Desktop` and existing guests are
preserved. Generated component manifests and all artifacts remain private.

2026-10-23: **`XP25-Desktop` is registered in system libvirt for interactive
virt-manager use.** Its independent disposable disk is sector-identical before
boot to the newest verified desktop checkpoint, `network-native-kvm-mp-02`
(18:35:27 UTC), and has no reference backing chain. The original two-vCPU
qemu32/512 MiB/i440fx/IDE/standard-VGA/RTL8139 profile is retained, with a
loopback VNC console and the isolated libvirt DHCP/DNS network. Explorer/Luna
and all four regression probes pass in the registered VM. Guest-requested
shutdown is recorded; the VM is left shut off with autostart disabled, ready
for the user to start. Existing guests and reference images are preserved.
[Configuration, commands and verification](virt-manager-xp25-desktop.md)

2026-10-23, Milestone 2: **native networking passes.** The original NT 5.1
`net/tcpip/winsock` helper builds with the native Microsoft toolchain and fixes
the SP3 helper's missing ntdll imports without a kernel/parser extension.
Fresh KVM, two-vCPU KVM and TCG clones pass IPv4 parsing, TCP/UDP loopback,
RTL8139 initialization, DHCP, controlled DNS and isolated HTTP. Desktop,
file/registry, pointer, session, Notepad and normal-shutdown regressions pass.
An independently rebuilt helper passes ten consecutive network runs, a real
guest-requested warm reboot and the full suite again; a separate cold-boot
child also passes. Public Internet access remains disabled by a private network
namespace with no uplink or default route. Source and frozen reference images
are intact. [Commands, hashes, failures and runtime evidence](native-networking-milestone.md)

Tracked launchers, source-pinned native build media, fresh-probe test media and
packet/server logs make the networking process repeatable on the prepared
Linux host. Native SCM/Winreg RPC stubs and headers were generated in build
copies for Milestone 3. The installed SCM was not replaced. Eight extended SP3
ntdll IPv4/IPv6 conversion exports remain absent; the matching original helper
does not require them. Native Ws2_32 also lacks the SP3 Unicode resolver exports
GetAddrInfoW, FreeAddrInfoW and GetNameInfoW. Other virtual NICs, IPv6, TLS,
games and sustained network/security testing remain unverified.

### Preserved Milestone 1 checkpoint

2026-10-23: **the source-kernel desktop milestone succeeds under KVM.** A fresh
clone loads XP25KRNL.EXE with compiled checksum `0x33bcdb`, reaches graphical
login, authenticates XP25, loads Explorer/Luna, passes registry and filesystem
round trips, saves/reopens a Notepad file and shuts down through the guest's
`shutdown.exe`. Live LsaLogonUser returns status/substatus zero; its logon ID
131677 matches the subsequent user and Explorer tokens. All 18 staged files
remain intact after normal shutdown. Snapshot `source-desktop-verified` and
frozen disk SHA-256
`655b3a363040e99160ab9ac595e2c2e232355dce8fe332ec8b4663384d6b3ca0`
preserve this result. [Full evidence and reproduction](source-desktop-milestone.md)

Matching original LSASRV/Secur32 resolves the TokenAuditPolicy mismatch without
an auditing bypass. The next shell failure, absent DecodePointer, is resolved
by `build/apply_pointer_compat.py`: a kernel-held per-process cookie with the
SP3 x86 self-only query (class **36**) and real encode/decode exports. Build-19
was rejected because incremental compilation skipped process allocation;
build-20 performs a clean rebuild and restores only the four documented supplied
executive objects. Eleven pointer checks and six session checks pass in fresh
KVM, TCG and two-vCPU KVM guests. Wrong TPR-class injection still bugchecks `0x9`.

The tracked `build/prepare_native_boot.py` and `build/native-boot-build.cmd`
pipeline has executed in build-21: four checked kernels, three HALs, ntdll and
Kernel32 compile/link using the supplied native tools. Its independent fresh
boot also reaches Explorer/Luna and passes the pointer/session probes and
normal shutdown. This pipeline requires the prepared native build
copy and four supplied executive objects; it is not a complete C/ASM OS rebuild.
At this earlier checkpoint the source-guest UDP probe failed (10022) because
SP3 wshtcpip needed `RtlIpv4StringToAddressExW`; Milestone 2 above resolves that
specific failure with the original helper. Games, accelerated graphics and
sustained stability remain unverified. The protected SP3 reference is intact.

### Earlier investigation checkpoints

Active boot investigation (2026-10-22): the running `xp25-sp3` reference now has
the libvirt disk-and-RAM snapshot `xp25-before-apic-debug-20261022`. New experiments
are isolated overlays in `.work/boot-debug-20261022/`, with per-run QEMU commands,
QMP journals and atomic checkpoint files. No reference guest files were changed.
Live GDB reproduces `KfLowerIrql`'s readback assertion at HAL RVA `0x23b1`:
requested TPR `0x3d`, observed `0x30`, IRQL APC_LEVEL (1). Disabling QEMU's VAPIC
optimization still fails; userspace APIC is rejected by this host KVM. TCG passes
this stage and reaches `KeBugCheck(0x71)` (`SESSION5_INITIALIZATION_FAILED`). Its
trace shows SP3 ntdll interpreting the SP1 inline syscall bytes at shared-data
offset `0x300` as pointer `0x340fd48b`. ABI correction experiments are ongoing;
no source-kernel login or desktop has been established. Later results below
supersede the initial APIC blocker.

The object-operation trace identifies the missing drive path as
`\??\C:\WINDOWS`. SP3 `mountmgr.sys` imports `ObIsDosDeviceLocallyMapped`,
absent from the source kernel; matching source MountMgr compiled successfully
in `build-03` (SHA-256
`338776e980cfa36977bdc84dd159acf342d0002948ac57c5395519f1f4c939ca`).
SP3 Win32k also requires absent `MmCommitSessionMappedView` and
`SeTokenIsWriteRestricted`; no substitute security implementations were added.

A clean kernel attempt compiled 1,859 files, including both patched kernel
files, then failed because `base/ntos/ex/exinit.c` and `systime.c` are missing.
Earlier successful kernel links depended on the four supplied i386 executive
objects. `build-04/prebuilt-inputs.json` records their hashes; restoring those
exact inputs allowed another native kernel link and corrected HAL build.
This is a mixed source/prebuilt kernel build, not a complete rebuild from C/ASM.
Fresh-clone boot verification is ongoing.

The completed HAL correction passes early initialization in the seven recorded
`matrix2-*` configurations (KVM/TCG, UP/MP, qemu32/host/Pentium III and ACPI PIC).
A deliberately wrong TPR class still triggers bugcheck `0x9`; the retained IRQL
guard is verified in `regression-wrong-irql/`. Matching source Win32k then built
and loaded. Live inspection identifies `XP25KRNL.EXE`, matching its compiled PE
checksum, and records SMSS and CSRSS, but no Winlogon. CSRSS exits with
`0xc0000003` after unsupported process-information calls. Matching native CSRSS,
CSRSRV and BaseSrv have since compiled successfully. The checked CSR output
identifies SP3 BaseSrv initialization as a failure; replacing it with the
matching native build advances to DLL initialization failure during WinSrv
loading. A loader-return trace records `0xc0000142`, and an entry-routine trace
shows SP3 Kernel32 returning FALSE on process attachment before User32 starts.
Original Kernel32 then compiled successfully (67 files). The next trace exposed
source GUI stubs executing the shared syscall pointer as inline code, faulting
at `0x7ffe0309`. The small `services.stb` correction selects the original INT 2E
entry with the caller arguments at `ESP+4`. Rebuilt User32/GDI32 contain the new
instructions; a fresh boot records successful Kernel32 and User32 process
attachment. Relinking WinSrv removes its remaining 22 old stubs and advances
to Winlogon, which terminates with status `0x80` before login. The display log
also identifies SP3 Framebuf's absent `EngBugCheckEx` import; the matching native
Framebuf driver compiled and removed that import error, although its hardware
pointer initialization fails and VGA fallback remains unverified.

The Winlogon exception is `0xc0000139`: SP3 ntdll dynamically requests
`Kernel32!BaseQueryModuleData`, absent from the SP1 source. Matching original
ntdll then built successfully, including its native ETW prerequisite. A fresh
boot passes that lookup stage and identifies a newer SP3 Winsock dependency,
`RtlIpv6StringToAddressExW`. Matching original Winsock and its helper then built.
Using matching IMM32 removes a subsequent embedded SP3 GUI syscall mismatch.
Fresh KVM and TCG clones reach the graphical XP login screen. At login, the
loaded kernel path is `\\WINDOWS\\system32\\XP25KRNL.EXE` and checksum `0x33f857`,
matching the compiled input. Snapshot `source-kernel-login-error` preserves the
KVM state; frozen disk SHA-256 is
`caafd03bda607791ffb3d1fd63c201c30c9b879dc0919502a2bd468dc6f3d4a7`.

Authentication fails: `LsaLogonUser` returns `0xc0000003` after LSASS attempts
`NtSetInformationToken` class 16 (`TokenAuditPolicy`), absent from the SP1
kernel. The captured request is 12 zero bytes. Matching original LSA compilation
is in progress. No token audit-policy failure has been bypassed.
The private import checker was corrected to include bound import rows; revised
checks supersede its earlier incomplete scans. No source-kernel authentication
or desktop has been established, and no assertion was ignored.
[Investigation and exact limitations](boot-investigation.md)

The resumption supervisor detected an actual usage limit, waited until the
recorded reset, and invoked `codex exec resume` with the existing session UUID.
Codex rejected it because the still-open TUI held an active thread writer. The
supervisor stopped on that non-usage error. Automatic CLI resumption requires
the existing writer to release the session; it cannot currently continue this
open TUI unattended. Evidence: `.work/resumption/` and
`boot-debug-20261022/resumption-tests.log` (six focused tests pass).

Four checked x86 kernels have been compiled, linked and inspected in the
supplied Windows guest, using the supplied executive objects for two missing
source files. Matching source NTFS, MountMgr, Win32k and checked HALs now build.
The APIC failure is corrected for the recorded virtual hardware; current boot
work stops during authentication after graphical login appears. Earlier failures remain
preserved. A complete custom OS image has not been established.
[Native build record](native-kernel-build.md), [current boot investigation](boot-investigation.md).
The supplied XP SP3 installation now boots in a local KVM guest. The corrected
native probe passes all six implemented checks; manual login and ACPI shutdown
have also been observed. [Guest baseline and evidence](xp-sp3-guest.md)
The guest is registered as `xp25-sp3` in system libvirt and its VMM console
was verified on the same development overlay.
The original source remains unchanged. No cloud deployment, GPU unbinding,
proprietary upload or public CI execution has occurred.

The baseline identifies NT 5.1.2600.1106 (XP SP1-era). x86 is the primary OS
target. Substantial AMD64 code exists, but no NT 5.2 product baseline or working
AMD64 OS has been established. [Architecture findings](architecture.md)

## Milestone 1 execution

| Action | Executed result | Local evidence |
| --- | --- | --- |
| Full inventory | 277,863 files, 6,322,952,743 bytes; all hashed | `.work/anniversary-milestone-1/inventory/` |
| Disposable staging | Complete copy verified against reference manifest | `.work/milestone-1-native-stage/result.json` |
| Checked x86 kernel attempt | Blocked at CMD launch; compiler not started | `.work/anniversary-milestone-1/build-x86-kernel/` |
| Checked x86 base attempt | Blocked at CMD launch; compiler not started | `.work/anniversary-milestone-1/build-x86-base/` |
| Experimental AMD64 kernel attempt | Blocked at CMD launch; compiler not started | `.work/anniversary-milestone-1/build-amd64-kernel/` |
| QEMU x86 firmware run | `harness_passed`; Windows boot `not_attempted` | `.work/anniversary-milestone-1/qemu-x86/` |
| QEMU amd64 firmware run | `harness_passed`; Windows boot `not_attempted` | `.work/anniversary-milestone-1/qemu-amd64/` |
| Image creation/custom boot | Not performed: linked OS payload absent | Aggregate `result.json` |

Reference, staged copy and fresh staged inventory all have manifest SHA-256
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
The retained native-launch error is `[Errno 2] No such file or directory:
'cmd.exe'`. This is a host-launch failure, not a compiler or kernel-source
failure. Native batch behavior was unverified at that checkpoint; the later
Windows execution record follows below. Firmware
screenshots, QMP observations and serial logs are retained.

Repeat with fresh paths:

```bash
python3 build/stage.py --output .work/next-stage
python3 build/milestone.py --source .work/next-stage/NT \
  --bios /usr/share/seabios/bios-256k.bin --output .work/next-milestone
```

The aggregate runner exits 2 because no custom OS boot is established. It does
not promote firmware execution or a zero native command exit to boot success.
On a compatible Windows build host, the batch wrapper can also run directly;
see [the native build runbook](build-vm-baseline.md).

## Native regression probe: compilation checkpoint

Implemented `tests/guest/xp_probe.c` and `build/guest.py`. A 22,939-byte x86 PE 5.1
probe compiled with MinGW GCC 13 using `-Wall -Wextra -Werror`, no C runtime,
and no Linux/Wine/ReactOS runtime dependency. Independent objdump inspection
confirmed the PE format and four permitted Windows DLL dependencies. All 48
named imports match local XP SDK import libraries. The executable SHA-256 is
`9442f469f533395ae911a7201450d95a86bbaf683d08dffb6a767ffafb859a9e`.

Evidence is under `.work/milestone-2-probe-final/`: `result.json`, `build.log`,
`inspection.txt` and `xp_probe.exe`. Six implemented observations cover guest
version, Explorer presence, volatile registry roundtrip, temporary-file I/O,
bounded UDP loopback and active driver-service enumeration. Login transitions,
games, security mitigations and shutdown remained explicitly untested at this
compilation checkpoint. Runtime results follow below.
[Guest instructions](../tests/guest/README.md)

The compiler was extracted privately, without system-wide installation. Its
driver reports `i686-w64-mingw32-gcc-posix (GCC) 13-posix`. Packages and tools are
retained under `.work/toolchains/`. MinGW builds the new probe only; native XP
kernel compilation still requires its original Windows toolchain environment.

## Supplied SP3 guest: 2026-10-18–19

Installed the user-supplied ISO on a new 32 GiB disk using QEMU 8.2/KVM,
`pc-i440fx-8.2`, `qemu32`, one CPU, 512 MiB RAM, IDE and no NIC. All artifacts
remain in `.work/xp-sp3-install-20261018/`. The ISO was attached read-only;
no Microsoft download, source upload or public CI was used.

Cirrus reached Setup but repeatedly failed the first-boot resolution transition.
Its state is preserved in snapshot `cirrus-oobe-blocked`. Standard VGA reached
the 640×480 Explorer/Luna desktop. Higher resolutions and accelerated graphics
are unverified; the hardware wizard still appears and was cancelled.

The guest reports XP Professional 5.1.2600 SP3, kernel 5.1.2600.6419. This is a
supplied runtime/build guest, distinct from the SP1-era source reference.

| Observation | Executed result | Evidence in the session directory |
| --- | --- | --- |
| Original probe | Five passes; enumeration fails with error 234 | `serial-xp-sp3-20261019-082323.log` |
| Corrected probe | Six passes, exit 0 under Administrator and XP25; 70 active drivers across two pages | Same serial log; `probe-paged/` |
| Logoff/login | Account chooser, XP25 desktop, passing probe | `51-logoff.png`, `52-xp25-login.png`, `53-xp25-probe.png` |
| ACPI shutdown | QMP `guest=true`, `reason=guest-shutdown` | `commands.jsonl` |
| Stopped disk | `qemu-img check` passes; image hashed and made read-only | `baseline-checkpoint.json`, `baseline-image-check.log` |
| Overlay reboot | Desktop and six probe passes from the hashed backing disk | `serial-native-build-20261019-083158.log` |
| Focused host checks | Five pass; reproducibility and allowed XP imports retained | `host-tests.log` |

The probe now handles `ERROR_MORE_DATA` through bounded enumeration pages rather
than assuming one exact allocation is enough. Its new SHA-256 is
`40f06be4905044ff91ed4acd858e91aac8ee82f0f5a7bd680bdfcca7fabc47f9`.
The old failing executable and logs are preserved.

Installed backing disk SHA-256:
`e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c`.
Native build work uses a separate qcow2 overlay. Detailed input hashes, versions,
commands, display limitations and restart instructions are in
[the guest runbook](xp-sp3-guest.md).

## Native checked x86 kernels

The guest copied all 277,863 expected source files with zero path/size mismatches.
Razzle's LF batch-label failure was resolved by converting 2,544 batch files to
CRLF in `C:\nt` only, with before/after hashes recorded. The original host
reference and transfer image retain their original bytes.

Native execution exposed two project-wrapper defects: quoted Razzle arguments
became literal quotes in TEMP/output environment values, and `build.exe` could
return zero after child NMAKE failures. The wrapper now passes the validated
short paths without embedded quotes and detects the observed failure marker and
nonempty error logs. Recorded failing and successful runs return 1 and 0.

Original `genlvl` and MC tools generated missing debug-filter, PCI and ISA PnP
prerequisites. Original boot-video and kernel-debugger sources produced the
required import libraries. No core C source implementation was replaced.

`C:\xpout\kernel-06` linked `ntoskrnl.exe`, `ntkrnlmp.exe`, `ntkrnlpa.exe` and
`ntkrpamp.exe`. All are native i386 PE files, version 5.1.2600.1106, with valid
independently recomputed checksums and only HAL/BOOTVID/KDCOM imports. The four
filenames correspond to the original UP/MP/PAE targets, but checked builds
force `NT_UP=0`. All runtime tests use one CPU; SMP behavior and AMD64 runtime
have not been established.

Evidence: `.work/xp-sp3-install-20261018/kernel-inspection.json`,
`native-extracted/`, `build-checkpoint.json` and the command/serial journals.
The frozen build disk SHA-256 is
`45301e5c36a678955881721a1f0c9f1014cd2c2a872284bb11951fd3b91c2fd6`.
The installed SP3 backing image retained its original hash. The post-build
probe still passed all six checks, and another ACPI shutdown was observed.

The first source-kernel selection stopped in NTLDR at the installed
`Ntfs.sys`. Its checksum is valid, but it imports
`SeAuditingFileEventsWithContext` and `SeAuditingHardLinkEventsWithContext`,
which the SP1-era source kernel does not export. Both are exported by the
installed SP3 kernel. A separate disk preserves that failure. The supplied NTFS
source uses the older interfaces. Matching NTFS and checked ACPI APIC HAL
builds have since succeeded and passed PE checksum/import checks. The NTFS-only
boot reached the kernel and stopped at `MISMATCHED_HAL` (0x79). With the
checked HAL selected, a live debugger captured `0x8e / STATUS_BREAKPOINT` at
the HAL APIC priority readback check: written `0x3d`, read `0x30` under KVM.
All experiments use disposable child disks. TCG retries reached initialization
and reset, without a captured primary bugcheck or verified source-kernel login.
That result remains unverified. Five focused host checks passed again after
the final changes (`host-tests-final.log`); `git diff --check` passed.
[Exact build steps, hashes and limitations](native-kernel-build.md)

## Regression verification

`python3 -m unittest discover -s tests -v` executes 15 passing checks on the
prepared host. Coverage includes inventory accuracy, source/output separation,
independent staging, blocked-launch evidence, real QEMU disk snapshots/input
preservation, API-contract rejection, reproducible forwarding DLLs, reproducible
probe compilation and rejection of additional runtime dependencies.

The final log is `.work/anniversary-milestone-1/tests.log`. Integration checks
need private prepared toolchains and source inputs; they skip when those are
absent. Host passes are not XP runtime passes. [Compatibility matrix](COMPATIBILITY.md)

Earlier One-Core-API work produced 28 statically verified API-set aliases per
architecture. None were installed. The pinned upstream remains separate; its
ReactOS core is not substituted for Microsoft's kernel, Winlogon or services.
[Reuse analysis](onecore-analysis.md)

## Verified blockers and remaining work

1. Windows guest/media, native compiler execution and x86 kernel linking are now
   established. The APIC readback failure and subsequent version mismatches are
   resolved for the recorded desktop configuration. Native Winsock helper
   integration resolves the historical UDP failure; the recorded isolated
   networking matrix passes.
2. Original Winlogon and two executive C files are missing, with additional
   licensing/font-driver references and literal gaps. The earlier SCM absence
   finding checked the wrong path: `base/screg/sc/server` contains the original
   services target. Its native build and runtime matrix now pass, followed by
   original SMSS. No substitute OS core was adopted.
3. Four source kernels are linked, with boot-video/debugger dependencies built.
   The checked ACPI APIC HAL and matching NTFS build and boot to a verified user
   desktop. A complete custom OS rebuild remains blocked by missing original
   source files and depends on the installed Microsoft user-mode components.
4. No identified NT 5.2 XP Professional x64 product baseline. AMD64 code and
   standalone PE32+ aliases are not evidence of a supported x64 XP build.
5. No physical hardware/passthrough or modern-driver tests. Host device nodes
   do not establish guest support.
6. AWS's documented import path omits XP and discontinued i386 imports on
   April 1, 2026. EC2 remains a platform/driver feasibility blocker.
   [AWS requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html)

Next native work: assess the compiled Regsvc/Msgina/UserEnv candidates with
component-specific compatibility tests, account for UserEnv's SP3 export gaps,
and build Explorer's remaining original private library dependencies.
Game fixtures, accelerated graphics, hardware and security validation remain
outstanding. The supplied SP3 guest and linked source kernels have separate
evidence; a full custom OS rebuild is still incomplete.
