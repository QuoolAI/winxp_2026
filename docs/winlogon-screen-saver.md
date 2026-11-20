# Screen savers and the idle lock in the XP25 Winlogon (roadmap R-0)

Worktree `xp25-modernization`, after Milestone 8.4. Evidence root
`.work/screensaver-20261119/` (`W`). Until this change the XP25 Winlogon ignored
USER's screen-saver notice: no screen saver ever started, so a password-protected
screen saver ("On resume, password protect") never locked an idle session, and
USER repeated the notice about twice a second for as long as the station stayed
idle (finding SA-0, [roadmap R-0](modernization-roadmap.md)).

## The contract

The original Winlogon source is not in the tree. The contract was reconstructed
from the parts that are:

- **USER** (`windows/core/ntuser/kernel/input.c` `IdleTimerProc`, `syscmd.c`
  `StartScreenSaver`). Once the input-idle time passes `ScreenSaveTimeOut` and no
  saver runs (`gppiScreenSaver == NULL`), USER posts
  `WM_LOGONNOTIFY(LOGON_INPUT_TIMEOUT)` to the logon process with argument 1
  ("start only if secure"). It also sends `SC_SCREENSAVE` to the foreground
  window, whose default handling posts argument 0 ("start"). An application that
  swallows `SC_SCREENSAVE` (a video player) therefore stops only a non-secure
  saver. Argument 2 means the monitor is powered off.
- **Registration** (`queue.c`). USER accepts a saver only from a process started
  with `STARTF_SCREENSAVER` whose parent is the registered logon process. It then
  stops the notices and lowers the saver's priority while it is idle.
- **NT savers check no password** (`shell/osshell/control/scrnsave/common/scrnsave.c`:
  "WinNT has the password check built into the security desktop"). A secure saver
  is a Winlogon lock.
- **MSGINA** (`ds/security/gina/msgina`). `WlxScreenSaverNotify` (WLX 1.1)
  returns TRUE and turns a secure request into `WlxIsLockOk`. Dialogs receive
  `WLX_WM_SAS(WLX_SAS_TYPE_SCRNSVR_TIMEOUT)`. The logon dialog returns FALSE "and
  lets winlogon kill us", so the host ends it with `WLX_DLG_SCREEN_SAVER_TIMEOUT`.
  The locked notice ends itself. Without Ctrl+Alt+Del (`DisableCAD`), the locked
  notice raises a SAS at once, and the logon and unlock dialogs have no timeout.
  So the saver must take over from the GINA's dialog, or it would never run.
- **Desktop.** NT 5.1's screen saver runs on `WinSta0\Screen-saver` (the name
  win32k's hard-error code and NetMeeting know).

## What the Winlogon does now

Portable rules in `components/winlogon/screensaver.c` (C89, host-tested); native
host in `screensaver_native.c`:

| Where (phase) | Settings | Runs as | Request 1 | Request 0 | After the saver |
| --- | --- | --- | --- | --- | --- |
| Logon desktop (signed out, logon dialog) | `HKU\.DEFAULT` | SYSTEM | starts | starts | logon desktop, SAS notice (the logon dialog) |
| Session, not secure | user's hive (policy key overrides) | the user | ignored | starts | back to the Default desktop |
| Session, secure (`ScreenSaverIsSecure` and `WlxIsLockOk`) | user's hive | the user | starts | starts | **session locked** |
| Locked station (locked notice or unlock dialog) | user's hive | the user | starts | starts | back to the locked station |
| Transitions, security-options dialog | — | — | counted only | counted only | — |

- At boot Winlogon creates `Screen-saver` next to `Winlogon` and `Default`. It
  grants SYSTEM full access. At logon it grants the user's logon SID
  read/enumerate/create-window/create-menu/write-objects. That grant excludes
  switch-desktop, hook and journal rights. Both are removed at logoff.
- A saver is started by Winlogon with `STARTF_SCREENSAVER` and
  `"<path>" /s`, on `WinSta0\Screen-saver`. The path is `SCRNSAVE.EXE`, expanded
  for that account; a bare name resolves in System32. Only a local drive path is
  accepted, because the logon desktop's saver runs as SYSTEM. A user's saver
  goes through the same identity-checked spawn as the shell, from a copy of the
  user's environment. Winlogon switches to the saver desktop and keeps the
  station switch-locked. Only the logon process can then change the desktop, so
  no application can bring the Default desktop back under a saver.
- An open GINA dialog gets the notice first (the WLX rule above). The saver
  starts when the GINA call returns, in place of the SAS notice or the locked
  notice.
- The saver's exit is observed through a registered wait. A **secure session
  saver ends in a lock**: `wl_session_lock`, the Lock notification, then
  `WlxDisplayLockedNotice`. If the session cannot be locked, Winlogon fails closed
  rather than return to the desktop. If a secure saver cannot be started, the
  session is locked without it.
- **Ctrl+Alt+Del** ends a running saver. After a secure one the session is locked
  first, so the SAS reaches the unlock dialog. **Win+L**, a logoff or a power
  request also end a running saver first. Task Manager's hotkey is ignored while
  a saver shows. Explorer recovery waits until the saver has ended.
- **Monitor off** (request 2): a secure session saver locks at once, with nothing
  to show. Otherwise the notice is counted.
- Notices that start nothing are counted, and recorded once per ten minutes
  (`screen_saver_not_started` and a reason), as in Milestone 8.4.

Serial records (and `native-winlogon.log`): `screen_saver_image_<file>`,
`screen_saver_started_{session,locked,logon_desktop}` (pid),
`screen_saver_secure`, `screen_saver_notices_during_run`,
`screen_saver_last_notice_ms`, `screen_saver_run_ms`, `screen_saver_ended`
(exit code), `screen_saver_returned_to_{desktop,locked,logon}`,
`screen_saver_secure_lock`, `screen_saver_stopped_by_{sas,lock,end_session}`,
`screen_saver_dialog_interrupted`.

Every XP25 image configures `logon.scr`, active, 600 s, not secure, in
`.DEFAULT`, the Default User hive and the XP25 profile (read offline from the
8.2 image). So an XP25 guest left idle for ten minutes now shows the Windows XP
logo saver, as stock XP does.

## Build

```sh
W=.work/screensaver-20261119 M=.work/modernization-20261118
python3 build/prepare_winlogon.py --output $W/wl-media-02
python3 vm/native_build_run.py --name ss-wl-build-02 --base $M/reference/build-vm-winlogon/disk.qcow2 \
  --media $W/wl-media-02/native-winlogon.iso --started XP25_WINLOGON_BUILD_STARTED --exit-marker XP25_WINLOGON_BUILD_EXIT
python3 vm/read_guest.py .work/boot-debug-20261022/ss-wl-build-02/disk.qcow2 $W/wl-collect-02 \
  /nt/xp25/winlogon/obj/i386/winlogon.exe /nt/xp25/winlogon/obj/i386/winlogon.pdb
```

CL 13.00 `/W4 /WX`, no warnings, `XP25_WINLOGON_BUILD_EXIT=0`. `winlogon.exe`
`020eaf4047dfeae7ed7ebdab507d951766e715065917430c9d6bb41f600e0f2b` (48,640
bytes), PDB `caefce1d…338b`. All 26 media files hash equal to the committed
`components/winlogon`. New imports: `RegisterWaitForSingleObject`,
`UnregisterWaitEx` (kernel32), `ExpandEnvironmentStringsForUserW` (userenv).
`ss-wl-build-01` was an earlier, superseded build: it compiled without warnings
but predates the unlock-dialog handover and was never run.

## Tests

**Host.** `tests/winlogon_screensaver.c` checks the documented cases, then every
phase × notice (including an unknown one) × setting × GINA answer against the
safety rules. A non-secure session saver never starts on request 1, and only a
session can be secure. A secure session saver always returns through a lock.
Nothing starts in transitional phases or without an image, and request 2 never
starts a process. Result: 6,732 checks, 0 failures, also under ASan/UBSan
(`tests/test_winlogon.py`). MinGW GCC `-fanalyzer` over the native file
(`build/static_analysis.py`): no analyzer finding.

**Guest.** `vm/winlogon_screensaver_probe.py` boots a fresh overlay of the frozen
8.2 image (`5a84781f…`) with this Winlogon installed offline. It stages
`tests/guest/screensaver_probe.c` (`3a8aad78…`; kernel32, user32 and advapi32
only) as an XP25 Startup program, which sets a 20 s timeout and `ssstars.scr`. The
driver then acts as the person at the console: one key to end each saver,
Ctrl+Alt+Del, Win+L, XP25's blank password, Enter at the logon dialog. Gates come
from the guest's own serial records, Winlogon's and the probe's. The probe adds what
a session program sees: `SPI_GETSCREENSAVERRUNNING` (true only for a saver USER
accepted) and which input desktop it can open.

```sh
W=.work/screensaver-20261119 M=.work/modernization-20261118 R=.work/security-20261111/reference
python3 vm/winlogon_screensaver_probe.py --name ss-up-02 --image $M/reference/XP25-CVE-Hardened-8.2.qcow2 \
  --image-sha256 5a84781f3adee8861f8b7e3cd5b57ee11778e87a3b7683111ebf9e31ba80eada \
  --probe $W/probe-01/screensaver_probe.exe --winlogon $W/winlogon-ss-02.exe
# ss-mp-02 adds: --cpus 2 --stage /WINDOWS/system32/xp25krnl.exe=$R/kernel-kx01/ntkrnlmp.exe \
#                --stage /WINDOWS/system32/xp25hal.dll=$R/mp/halmacpi.dll
# ss-tcg-02 adds: --accel tcg      ($W/run-matrix.sh runs all three)
```

| Gate | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| `logon` | Pass | Pass | Pass |
| `nonsecure_saver`: ssstars.scr as XP25, USER reports it, input desktop `Screen-saver`; a key returns to `Default`; no lock | Pass | Pass | Pass |
| `notices_stop`: notices during a run of ≥ 8 s, and the last one after the start | Pass (5; 250 ms) | Pass (10; 250 ms) | Pass (0 in a 47 s run) |
| `secure_saver_key`: a key ends a secure saver → session locked (Lock notification), input desktop not openable; blank password unlocks | Pass | Pass | Pass |
| `secure_saver_sas`: Ctrl+Alt+Del during a secure saver → saver stopped, session locked, unlock dialog; unlocked | Pass | Pass | Pass |
| `locked_station_saver`: Win+L, then the user's saver interrupts the unlock dialog; a key returns to the locked station; unlocked | Pass | Pass | Pass |
| `logon_desktop_saver`: after logoff, `logon.scr` (SYSTEM, not secure) interrupts the logon dialog; a key brings the dialog back | Pass | Pass | Pass |
| `relogon` (probe restores `.DEFAULT`) | Pass | Pass | Pass |
| `no_failure` | Pass | Pass | Pass |

Screenshots (evidence only) are in each run directory. Examples: `a1-saver`
(Starfield), `b2-locked` (MSGINA's Unlock Computer), `e2-saver` (the logon
desktop's Windows XP logo).

Under TCG the driver waits 16 s after each lock before typing the password.
The locked station stayed idle past the 20 s timeout, so the user's saver also
started on the locked station after the `secure_saver_key` and `secure_saver_sas`
locks, and twice in the locked case. This is correct: a locked, idle station runs
the saver. Each of the 5 interrupted dialogs (4 unlock dialogs, 1 logon dialog)
was followed by exactly one saver start and one return.

`runs/ss-up-01` is **kept as failed** (`failure.json`). Every guest action
happened as designed, and all probe cases passed. But the harness read the run
statistics after `screen_saver_ended` (Winlogon logs them before it). It also
captured the records as soon as `screen_saver_started_session` appeared, before
the following `screen_saver_secure` line reached `serial.log`. `notices_stop` and
`secure_saver_sas` therefore failed. The harness now reads records when the gate
is decided, and the reruns are `-02`.

## Harness: lost COM1 lines

Winlogon opens COM1 exclusively for each line and drops the line when the port is
busy (roadmap R-0b). On the XP25-Winlogon-Fix VM's disk this lost single lines,
and once a burst of lock-notification lines, in three verification runs
(`.work/vm-redeploy-20261119/runs/image01-ss-up-0{1,2,3}`, kept as failed). Each
time Winlogon's own `native-winlogon.log` showed the guest behaving correctly.
Since then the harness and the probe work as follows:

- The driver types an unlock only while the unlock dialog is on screen. It
  counts MSGINA's unlock result (`gina_unlock_result` 8) as well as
  `SensUnlockEvent`.
- The probe waits 2 s after each transition before writing, so Winlogon's
  records go first.
- At the end the driver turns the guest off through Start → Turn Off Computer,
  which flushes the guest's file logs. It reads `C:\xp25\native-winlogon.log`
  (records since this boot) and `C:\xp25\saver-probe.log` from a read-only copy
  of the overlay.
- The gates are decided once, from the serial and file records merged in order.
  `result.json` also keeps the serial-only verdict. The locked-station case is
  anchored on the first unlock after the Ctrl+Alt+Del case, because under TCG
  the user's saver can also run on the station while it waits to be unlocked.

Replaying the new evaluation on the recorded serial logs gives the same verdicts
for `ss-up-02`, `ss-mp-02` and `ss-tcg-02` (10/10).

## Regression

The same Winlogon (`020eaf40…`) went through Milestone 8.4's Winlogon regression
on overlays of the accepted 8.2 image. The proof and standard-user runs carried
AI build 17, as in 8.4. Runs went one at a time; `W/regression.sh` lists the
commands.

| Run | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| Two-account switch oracle (9 switches, wrong password refused) | Pass, 9/9 painted (`r0-switch-2acct-up-01`) | Not run | Not run |
| Winlogon lifecycle harness, main tree: 18 gates, then lock/unlock after a switch, restart and relogon, Turn Off, normal finish | Pass (`r0-wl-life-up-01`) | Pass (`r0-wl-life-mp-01`) | Pass (`r0-wl-life-tcg-01`) |
| Security lab `proof`: logon, licensing, Explorer, AI suite, compatibility suite, security probes, programs and games, network | Pass, 35/35 | Pass, 35/35 | Pass, 35/35 |
| Security lab `standard-user` | Pass, 12/12 | Not run | Not run |

No screen saver started in any of these runs: none of them idled for ten
minutes. So the saver neither disturbed them nor was exercised in them; the
screen-saver probe covers it. The lifecycle runs are under the main tree's
`.work/boot-debug-20261022/r0-wl-life-*`, the others under `W/runs/`.

## Limitations

- Fast User Switching and the Welcome screen remain unimplemented, so the
  Welcome-screen variant of "password protect" is not available.
- Request 2 (monitor off) is implemented but **not tested**: the harness does not
  drive a monitor power-down.
- Display Properties was not used. The probe set the values in the registry and
  through `SystemParametersInfo`. Winlogon reads the registry at each notice.
- `.DEFAULT`'s saver runs as SYSTEM, as on stock XP. Only a local drive path is
  accepted, and `.DEFAULT` is writable only by administrators.
- Group Policy screen-saver settings are honoured from the user's
  `Software\Policies` key only. Machine policy is not read.
