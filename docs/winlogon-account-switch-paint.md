# Account-switching logon controls — root cause and fix

Worktree `xp25-winlogon-ui` (branch `xp25-winlogon-ui`). Evidence roots:
`.work/winlogon-ui-20261113/` (`W13`, the first investigation) and
`.work/winlogon-ui-20261116/` (`W16`, root cause, fix and verification).
Lifecycle runs are under the main tree's `.work/boot-debug-20261022/` (`L`), made
with the Winlogon milestone harness `.work/winlogon-licensing-20261025/` (`WL`).

**Status:** root cause established from guest evidence; fixed in
`components/winlogon` (one comctl32 reset after the logoff that empties the
atom table); the fixed binary is verified on fresh overlays under one-vCPU KVM,
two-vCPU KVM and TCG. The accepted images (`XP25-Security-Baseline-8.1`
`501c7986…`, `XP25-CVE-Hardened-8.2` `5a84781f…`) and the XP25-Security-8.1 VM
still carry the unfixed Winlogon `e3a9cdca…`; they were not changed. Since
2026-11-18 the engineering image `XP25-Winlogon-Fix-8.2` (`fe633d15…`, the 8.2
image with only `winlogon.exe` replaced) carries the fix. It passed the
two-account oracle (9/9) and backs the virt-manager VM
[XP25-Winlogon-Fix](virt-manager-xp25-winlogon-fix.md).

## Symptom

On the first logon after boot the classic logon dialog's **User name** and
**Password** edits render correctly. After an account switch (logoff → the
dialog is shown again) the dialog paints fully except the two edits, which are
flush grey: no white fill, no sunken border, no user name. With the corrected
oracle (`vm/winlogon_switch_probe.py`) this is a strict alternation — switches
1, 3, 5, 7 blank, 0, 2, 4, 6 painted (`W13/runs/base-fixed-01`).

It is not only cosmetic. A blank edit also ignores typing. In
`W16/runs/stock-2acct-up-01` (the image's own Winlogon, two accounts) the first
switch offered `XP25B` with both fields blank; the typed password never reached
the edit, its first letter acted as the dialog's **S**hut Down mnemonic, MSGINA
returned `WLX_SAS_ACTION_SHUTDOWN_POWER_OFF` (10) and the guest powered off
(QMP `SHUTDOWN`, `guest-shutdown`). This is the failure the Milestone 8.1
standard-user runs met (`std-up-02/03`) and worked around with restarts.

## Root cause

1. At every successful user logoff, win32k's `EndShutdown`
   (`windows/core/ntuser/kernel/exitwin.c:407`) empties the window station's
   global atom table: `RtlEmptyAtomTable(pwinsta->pGlobalAtomTable, FALSE)`.
   CSR's `_ExitWindowsEx` calls it before returning, so it has run when the
   Winlogon's own `ExitWindowsEx(EWX_LOGOFF)` returns
   (`windows/core/ntuser/server/exitwin.c`).
2. comctl32 keeps its window-subclass data in a window property keyed by the
   global atom `CC32SubclassInfo`, and **caches that atom** in
   `g_aCC32Subclass`. It adds the property by string (a fresh atom after the
   purge) but looks it up by the cached atom (`shell/comctl32/v5/subclass.c`,
   `SetSubclassHeader` / `FastGetSubclassHeader`).
3. MSGINA subclasses exactly the logon edits through comctl32:
   `SetWindowSubclass(IDD_LOGON_NAME/IDD_LOGON_PASSWORD, DisableEditSubClassProc)`
   (`ds/security/gina/msgina/mslogon.c:1045`; the unlock edits likewise,
   `mslock.c:717`).
4. When the fresh atom differs from the cached one, comctl32's master subclass
   procedure finds no subclass data, takes `SubclassDeath` and resets the window
   procedure to `ZombieWndProc`, which is `DefWindowProc` in retail builds. A
   `DefWindowProc` window draws nothing and does not accept characters.
5. comctl32 defines the remedy for exactly this case (`InitForWinlogon`):
   *"for C2 security reasons, all global atoms are nuked from the window station
   when you log off. So the rule is that all winlogon clients of comctl32 must
   call `InitCommonControlsEx(ICC_WINLOGON_REINIT)`"*. In comctl32 5.82 this
   re-adds the atom, re-keys existing subclassed windows and refreshes the cache
   (`FixupSubclassRecordsAfterLogoff`, called at `0x5d0d1371`). The XP25
   Winlogon never made that call.

Why period 2: after each purge the station hands the `CC32SubclassInfo` atom
alternately `0xC017` and `0xC019`, while comctl32's cache stays `0xC019`.

## Evidence

**The blank edit's window procedure is `DefWindowProcW`.** A trace build
(`W16/winlogon-trace01.exe` `cdde0da4…`, `W16/trace-01.patch`) subclassed the
two edits read-only after MSGINA's `WM_INITDIALOG` and logged every paint
message (`W16/runs/trace01-up-01`). In painted dialogs the edits' procedure is
`0x5d09607d`, inside `system32\COMCTL32.dll` 5.82 just past `DefSubclassProc`
(comctl32's unexported master subclass procedure). In blank dialogs it is
`0x69e4a4ce`, which the export table of the image's `user32.dll`
(`a51976dd…`) resolves to **`DefWindowProcW`**: `WM_ERASEBKGND` returns 0, no
`WM_CTLCOLOREDIT` is ever sent, and `WM_PAINT`/`WM_PRINTCLIENT` draw nothing.
The earlier reading — "painted in win32k but not reaching the framebuffer" —
was wrong: the control never draws.

**The atom mismatch alternates exactly with the blank cycles.** Two further
trace builds read comctl32 5.82's cached atom (`g_aCC32Subclass`, a WORD at
RVA `0x720bc`, found from the code that stores the `GlobalAddAtomW` result),
the station's current atom (`GlobalFindAtomW`) and both property lookups, at
each logon dialog and after each logoff (`W16/trace-02.patch`, stock code;
`W16/trace-03.patch`, with the fix). Summary (`W16/atom-trace-summary.txt`):

| Cycle | Stock: cached / station atom | Stock: edit procedure | Stock: oracle | Fixed: cached / station | Fixed: edit procedure | Fixed: oracle |
| --- | --- | --- | --- | --- | --- | --- |
| 0 (boot) | `C019` / `C019` | comctl32 subclass | painted | `C019` / `C019` | comctl32 subclass | painted |
| 1, 3, 5, 7 | `C019` / **`C017`** | **`DefWindowProcW`** | **blank** | `C019` / `C019` | comctl32 subclass | painted |
| 2, 4, 6 | `C019` / `C019` | comctl32 subclass | painted | `C019` / `C019` | comctl32 subclass | painted |

In the blank cycles `GetProp(edit, cached atom)` fails while
`GetProp(edit, "CC32SubclassInfo")` succeeds. That is the stale cache. After
every logoff both builds log the station atom as `0000` (purged); in the fixed
build the reset re-adds it as `C019` before the next dialog. The read of
comctl32's private global exists only in the trace builds, never in the
committed code.

**The original Winlogon makes this call.** Microsoft's `winlogon.exe`
(`7cd68891…`) registers an internal notification named `Reset ComCtl32`
(`0x10321c9`; which session event its mask selects was not established). Its
handler (`0x1032c67`) calls
`GetModuleHandleW(L"COMCTL32")`, `GetProcAddress(…, "InitCommonControlsEx")`
and calls it with `{8, 0x80000000}` (`ICC_WINLOGON_REINIT`), then repeats this
for the COMCTL32 of its activation context. This explains the earlier control
result, where Microsoft's Winlogon paints after a logoff on a byte-identical
display stack (framebuf/win32k/gdi32).

**Why the earlier attempts could not work.** Dialog repaint, desktop re-blit,
`WS_CLIPCHILDREN`, lock ordering, switch-away-and-back and a background window
all act on painting or desktop presentation. By then the controls are already
`DefWindowProc` windows, so there was nothing to repaint. The desktop-switch,
`SwitchDesktop` and surface hypotheses of the first write-up are withdrawn.

## The fix

`components/winlogon/gina.c` adds `wl_common_controls_reset()`, which calls
`InitCommonControlsEx({sizeof, ICC_WINLOGON_REINIT})` of the loaded
`comctl32.dll` (resolved with `GetModuleHandleW`/`GetProcAddress`, so the import
table is unchanged — 141 imports, identical to `e3a9cdca…`).
`components/winlogon/session.c` calls it in `native_end_processes` directly
after the Winlogon's own `ExitWindowsEx(EWX_LOGOFF)` succeeds. That is the call
whose end of session emptied the atoms. It is the engine's `end_processes`
driver operation, so every path that ends a user session runs through it:
`wl_engine_logoff` (user, GINA, Windows Security, locked and pre-power-off
logoffs) and `wl_engine_abort` (rollback after a shell start was attempted).
It runs before any later GINA dialog. The result is logged as `comctl32_winlogon_reset`. Nothing
else changes: authentication, licensing admission, security descriptors,
desktop switching and session ordering are untouched. No sleep or repaint was
added. The winlogon process has no activation context, so only the system32
comctl32 5.82 (`853c4a03…`) is loaded. The traces show the logon edits are
subclassed through it.

## Verification

Binary under test: `W16/winlogon-fix01.exe`, SHA-256
`63308b0f9c6a2bec4692a5ff879e6dcd86d49b1ae6a711659f6c1ca933017cf8`, 43,008
bytes, PDB `0fab721b…`. It was built natively in the frozen build VM
(`wl-build-12`, `/W4 /WX`, 15 files compiled, no warnings, no
`nmake.exe failed`) from media `W16/wl-media-fix01` (ISO `feaf9959…`). The
committed source differs from that build only in the wording of one comment.
It was rebuilt as `W16/winlogon-fix02.exe` (`wl-build-15`, SHA-256
`f24bba5b2561b183a33d1cda106941138c28b1cc8dc50fde79f23f4511f733d3`, PDB
`7820593c…`, media ISO `c5d360d9…`, all 23 sources byte-identical to the
committed tree). `build/compare_pe.py` finds `fix01` and `fix02` equal after
normalization: only the checksum, COFF and debug time stamps and the PDB
signature differ, with no other differing byte. `fix02` was also run directly
(below).

### Pixel oracle on the 8.1 image (`XP25-Security-Baseline-8.1` `501c7986…`)

Each run is a fresh NIC-free overlay with only `winlogon.exe` replaced (plus the
verified MP kernel/HAL for two vCPUs). The two-account mode creates `XP25B`
(password `sw1tch25`) in the first session and alternates `XP25` ↔ `XP25B`
through logoff. Each cycle measures both fields in two captures 4 s apart
(painted: ≥ 60 % white; observed 0.977/0.969 user name, 0.996 password, blank
0.0), confirms each logon from the Winlogon's serial SID record, and in
cycle 3 first enters a wrong password, which must be refused.

| Run | Winlogon | Mode | Switches painted (both fields, both captures) | Accounts | Wrong password |
| --- | --- | --- | --- | --- | --- |
| `W13/runs/base-fixed-01` | stock `e3a9cdca…` | 1 vCPU KVM, one account | 3/7 (alternating) | — | — |
| `W16/runs/stock-2acct-up-01` | stock `e3a9cdca…` | 1 vCPU KVM, two accounts | **0/1**: switch 1 blank; logon impossible, guest powered off | 1 | — |
| `W16/runs/fix01-up-01` | fixed | 1 vCPU KVM, one account | **7/7** | — | — |
| `W16/runs/fix01-2acct-up-01` | fixed | 1 vCPU KVM | **9/9** | 1003 ↔ 1008, 10 logons | refused (MSGINA logon message), dialog painted after it |
| `W16/runs/fix01-2acct-mp-02` | fixed | 2 vCPU KVM, MP kernel `42662074…` + HAL `69ca3e71…` | **9/9** | 1003 ↔ 1008, 10 logons | refused |
| `W16/runs/fix01-2acct-tcg-01` | fixed | TCG | **5/5** | 1003 ↔ 1008, 6 logons | refused |
| `W16/runs/fix02-2acct-up-01` | fixed, final build `f24bba5b…` | 1 vCPU KVM | **9/9** | 1003 ↔ 1008, 10 logons | refused |

No input retries were needed in any fixed run.

### Winlogon lifecycle regression (engineering image, isolated network)

`WL/launch-native.py` installs only the fixed `winlogon.exe` on the
hash-verified engineering image (22 component hashes checked before and after;
the MP mode uses the verified MP engineering base). `WL/lifecycle.py` decides
every gate from serial records. `W16/after-switch-power.py` then continues in
the re-logged-on session (after a logoff), then `WL/desktop-power.py shutdown`
and `WL/finish-normal.py`.

| Gate | 1 vCPU KVM `L/wl-switchfix-kvm-01` | 2 vCPU KVM `L/wl-switchfix-kvm-mp-01` | TCG `L/wl-switchfix-tcg-01` |
| --- | --- | --- | --- |
| Wrong password rejected; logon; licensing admission; Explorer identity | pass | pass | pass |
| xp/session/service/shell probes (incl. Luna active), no failed case | pass | pass | pass |
| `Win+L` lock, password unlock; Task Manager hotkey; Windows Security cancel | pass | pass | pass |
| Explorer killed → recovered; logoff (no LUID processes); relogon | pass | pass | pass |
| Isolated network probe | 17/17 | 17/17 | 17/17 |
| Lock and unlock **after the account switch** (unlock dialog painted) | pass | pass | pass |
| Desktop Restart → guest `RESET` → reboot → logon dialog → relogon | pass | pass | pass |
| Desktop Turn Off → guest-requested `SHUTDOWN`; overlay frozen | pass (`660baf31…`) | pass (`b28b0688…`) | pass (`2a7baae7…`) |

### Host tests

`python3 -m unittest discover -s tests`: 134 tests pass (15 skipped because
their private inputs are not in this worktree's `.work`). The session
coordinator under AddressSanitizer/UBSan (the `CLAUDE.md` command) reports
`cases=52 checks=913 failures=0`. The new `tests/test_winlogon_switch_probe.py`
checks the oracle without a guest: field and dialog detection on synthetic
frames, SID parsing, and refusal of inconsistent options. The portable C core
is unchanged; the fix is in the native adapters, which only the guest runs
above exercise.

## Failures and corrections kept

* `W16/runs/fix01-2acct-mp-01`: bugcheck `0x7E` (`C0000005`) before the
  Winlogon's first record (empty `serial.log`). This was an operator error: two vCPUs
  on the 8.1 image's uniprocessor HAL, the known failure recorded in
  [PROGRESS](PROGRESS.md) (`fstab-mp-*`). `mp-02` stages the verified MP
  kernel/HAL as the security lab does.
* An attempt to start the MP and TCG oracle runs failed in the host shell (empty
  paths); no guest started.
* The oracle's PNG conversion (`qemu-img convert -f ppm`) never worked; the
  `screenshot` fields of runs before this fix name `.png` files that do not
  exist. The `.ppm` screendumps are the evidence; the oracle now records them.
* The first write-up's claims that the paint "does not reach the framebuffer"
  and that the fault lies in desktop presentation are withdrawn (see Evidence).

## Limitations

* The fix is not in the accepted 8.1 and 8.2 images or the XP25-Security-8.1
  VM; those still show the defect. It is installed in the engineering image
  `XP25-Winlogon-Fix-8.2` (`fe633d15…`) and the XP25-Winlogon-Fix VM. On that
  image only the one-vCPU KVM oracle was run; the MP, TCG and lifecycle results
  come from overlays of the 8.1 image.
* The unlock dialog after a switch was observed painted (and unlocked) with the
  fix on the engineering image. Its stock behaviour after a switch was not
  separately measured.
* comctl32 v6 (side-by-side) is not loaded by this Winlogon. If a future
  manifest or GINA brings it in, it needs the same reset (as the original
  Winlogon does for its activation context).
* The logoff in `EndShutdown` also unloads non-permanent fonts
  (`GreRemoveAllButPermanentFonts`). This change does not address that; no
  font defect was observed here.

## Reproduction

```sh
W16=.work/winlogon-ui-20261116
python3 build/prepare_winlogon.py --output $W16/wl-media-NEW
python3 vm/native_build_run.py --name wl-build-NEW --base .work/winlogon-ui-20261113/reference/build-vm-disk.qcow2 \
  --media $W16/wl-media-NEW/native-winlogon.iso --started XP25_WINLOGON_BUILD_STARTED --exit-marker XP25_WINLOGON_BUILD_EXIT
python3 vm/read_guest.py .work/boot-debug-20261022/wl-build-NEW/disk.qcow2 $W16/collect-NEW \
  /nt/xp25/winlogon/obj/i386/winlogon.exe /nt/xp25/winlogon/obj/i386/winlogon.pdb
IMG=.work/winlogon-ui-20261113/reference/XP25-Security-Baseline-8.1.qcow2
SHA=501c79862d41824a2748c96f5b4715f22ba25443630cb1e3ff0c13674999fda4
python3 vm/winlogon_switch_probe.py --name RUN --image $IMG --image-sha256 $SHA \
  --probe .work/winlogon-ui-20261113/security_probe.exe --winlogon WINLOGON.exe \
  --second-user XP25B --second-password sw1tch25 --wrong-password-cycle 3 --cycles 10 --out-root $W16/runs \
  [--accel tcg --cycles 6] [--cpus 2 --stage /WINDOWS/system32/xp25krnl.exe=$W16/reference-mp/ntkrnlmp-kx01.exe \
   --stage /WINDOWS/system32/xp25hal.dll=$W16/reference-mp/halmacpi.dll]
# lifecycle (from the main winxp_2026 tree):
python3 .work/winlogon-licensing-20261025/launch-native.py NAME up|mp|tcg WINLOGON.exe
python3 vm/xp_lab.py .work/boot-debug-20261022/NAME qmp cont
python3 .work/winlogon-licensing-20261025/lifecycle.py NAME [--slow]
python3 <xp25-winlogon-ui>/$W16/after-switch-power.py NAME [--slow]
python3 .work/winlogon-licensing-20261025/desktop-power.py NAME shutdown
python3 .work/winlogon-licensing-20261025/finish-normal.py NAME desktop-shutdown-event.json "TRIGGER"
```

`W16/reference-mp/` holds read-only copies of the Milestone 8 references
`kernel-kx01/ntkrnlmp.exe` and `mp/halmacpi.dll`, hash-checked against their
manifest. Trace builds are made by applying `W16/trace-0N.patch` to the
committed tree; they are never committed. `Source/` is untouched; the frozen
base images are unchanged.
