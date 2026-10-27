# Independent Winlogon: licensing admission, desktop and session lifecycle

2026-10-25. Continuation of [the policy/session contract work](winlogon-policy-session-contract.md).
Evidence root `W=.work/winlogon-licensing-20261025`; experiments are under
`L=.work/boot-debug-20261022`. Every command is journaled in `W/commands.jsonl`
with its log beside it.

## Result

The independent NT 5.1 Winlogon now **boots, authenticates, admits the session
through the installed licensing agent, starts the original Explorer with Luna,
and runs the session lifecycle**: lock/unlock (API and `Win+L`), the Windows
Security dialog, Task Manager (`Ctrl+Alt+Del` and `Ctrl+Shift+Esc`), shell crash
recovery, logoff with process-exit verification, re-logon, and shutdown from the
desktop or from the signed-out GINA. The final binary is build 10,
SHA-256 `e3a9cdca26ab7af5ae5b225d647c94be0dc34aa4f7428e025ddf3b3c3becdf93`.
It passes 18 lifecycle/regression/network gates under single-vCPU KVM,
two-vCPU KVM and TCG, each run ending in a guest-requested shutdown event; a
separate desktop restart cycle (guest reset, reboot, re-logon) also passes.

This is not full parity with the original Winlogon. The precise remaining gaps
(Terminal Services session state, logon-desktop theming and post-logoff GINA
edit painting, the Welcome screen, Fast User Switching, event sounds, Group
Policy processing) are listed under [Known gaps](#known-gaps-and-defects).

## Licensing admission without fabricated results

The policy blocker (error 120) is replaced by a decision from the supplied
licensing agent, `licdll.dll` `COMLicenseAgent`, using exactly the sequence of
SP3 Setup's own `Activationrequired` check. Nothing is forced, cached or read
from WMI; any agent failure fails closed with its real error.

| Contract element | Evidence |
| --- | --- |
| CLSID `{ACADF079-CBCD-4032-83F2-FA47C4DB096F}` | licdll.dll `REGISTRY` resource (`W/licdll-registry.rgs`) |
| `ICOMLicenseAgent` `{B8CBAD79-3F1F-481A-BB0C-E7BBD77BDDD1}`, dual, stdcall; `Initialize` vtable slot 7 (+28), `GetExpirationInfo` slot 48 (+192) | licdll.dll `TYPELIB` parsed by `build/typelib_dump.py` (`W/licdll-typelib.json`); re-verified at runtime against the installed DLL's type library before any call |
| `Initialize(0xC475, 1, NULL, &status)`; status must be 0; activated iff `WPALeft == 0x7FFFFFFF` | SP3 `syssetup.dll` call site 0x69771b7c–0x69771bd6 (`W/initialize-callers-syssetup.dll.log`); same constants in SP3 `msobmain.dll` and `oobebaln.exe`; SP1 source `base/ntsetup/syssetup/utils.cpp` |
| licdll.dll SHA-256 `0b49d5b5…1f4e` | read-only extraction from the frozen build disk |

`policy.c:wl_policy_from_license` maps the outputs: activated or within the
grace/evaluation period → allowed with all three evidence bits (key protection,
agent initialization, activation); zero days of grace or evaluation → denied
(`ERROR_ACCESS_DENIED`, with an activation message instead of the generic
rollback text); any agent/COM error, non-zero `Initialize` status, malformed
output or missing key protection → unavailable with that error. 14 mapping
cases plus coordinator admission/rollback run in the host suite.

The first attempt used the WMI provider's arguments (`licwmi.dll`: BPC 0xC475,
mode 0); the guest returned `Initialize` status 87, the session failed closed and
rolled back (`L/wl-licensing-kvm-01`). Mode 1 is what Setup uses; with it every
run records status 0, `WPALeft` and `EvalLeft` 2147483647, verified mask 7.
Shell recovery re-runs the same admission. Activation reminders and launching
the activation wizard after grace expiry are not implemented; expiry denies logon.

## Missing Winlogon duties found and implemented

Each item was found from a runtime failure or an original-host comparison:

| Duty | Finding | Change |
| --- | --- | --- |
| `WlxWin31Migrate` | MSGINA `ExecProcesses` calls it on every TS-capable logon; host treated it as fatal (`L/wl-licensing-kvm-02`) | validate handle and return |
| Permanent font load, `user32!LoadLocalFonts` | userinit blocked before `StartTheShell` in `win32k!xxxLW_LoadFonts(TRUE)` waiting for `bPermanentFontsLoaded`; captured from guest memory (`W/up-05-stall-capture`, `vm/inspect_threads.py`) | background thread at boot (the `win32k` comment and the user32 export marked `; winlogon`) |
| Logoff process-exit wait | CSR ends processes during `ExitWindowsEx`, but exit can complete afterwards; host reported `ERROR_BUSY` and went fatal | bounded wait for every process of the logon LUID, then rescan |
| `UpdatePerUserSystemParameters` | original imports it; per-user metrics, keyboard layouts, wallpaper | as the user after desktop protection; defaults (`.DEFAULT`) after logoff |
| Logon-process hotkeys | `Win+L` and `Ctrl+Shift+Esc` are registered by Winlogon, not Explorer | `RegisterHotKey`, acted on only in an idle interactive session |
| `LOGON_RESTARTSHELL` | USER announces shell death | immediate shell check instead of waiting for the poll |
| `WlxRemoveStatusMessage` | status dialogs shown by notification packages were never removed | removed before the user desktop and before the next SAS notice |
| `WLX_OPTION_SMART_CARD_PRESENT` | MSGINA queries it; host returned an error | reports none (this host does not monitor readers) |
| MSGINA theme handoff (ordinal 10, `ShellNotifyThemeUserChange`) | original imports it; installed export verified as the documented two-argument switch | `ULT_LOGON` after protection, `ULT_STARTSHELL` before activation, `ULT_LOGOFF` after logoff |
| Shell identity after a crash | TCG build 08: recovery failed with error 8 while the dead shell's window could still be reported (`L/wl-licensing-tcg-01`) | a terminated owner or a transient module-snapshot failure means "not yet"; token/path mismatches stay fatal; failing operation is logged |
| COM1 diagnostics | one exclusive serial open per event-sound notice starved guest software of COM1 (lost probe output) | event-sound notices are not logged |

## Native builds

All built with the original NT toolchain (`build.exe -cZ`, `/W4 /WX`) in disposable
overlays of the build VM; every extracted source was compared to the working tree.

| Build | SHA-256 | Bytes | Outcome |
| --- | --- | --- | --- |
| 01 | `73d32108…e375` | 40,960 | agent created, ABI verified, `Initialize` status 87 (mode 0) → fail closed |
| 02 | `ab3ed513…3272` | 40,960 | admission allowed; `WlxWin31Migrate` fatal |
| 03 | `63f20dad…323f` | 40,960 | shell activated; userinit never started Explorer |
| 04 | — | — | **compiler failure** C4701/C2220 (`stats`), retained `W/build-04-failure-native.log` |
| 05 | `26fdf6a1…67d5` | 40,960 | same stall, memory captured, root cause found |
| 06 | `616a5bcf…3e04` | 41,472 | first interactive Explorer/Luna desktop; probes, lock, security dialog, Task Manager, recovery, logoff |
| 07 | `c375d0f0…febc` | 42,496 | hotkeys, status removal, dialog diagnostics |
| 08 | `dc2f7336…3470` | 43,008 | theme handoff; desktop shutdown; MP lifecycle |
| 09 | `b86dadea…a8c5` | 43,008 | COM1 noise removed; UP and MP accepted |
| 10 | `e3a9cdca…df93` | 43,008 | crash-recovery identity hardening; **final** |

## Runtime matrix, build 10

Each run is a fresh overlay of a hash-verified engineering image with only
`winlogon.exe` replaced (all 22 recorded component hashes checked before and
after; original Winlogon `7cd68891…25ea` kept as `recovery-winlogon.exe`), in an
isolated network namespace with an RTL8139 NIC. `W/lifecycle.py` decides every
gate from the guest's own Winlogon/probe serial records or QMP events.

| Gate | KVM 1 vCPU `wl-licensing-kvm-11` | KVM 2 vCPU `wl-licensing-kvm-mp-03` | TCG `wl-licensing-tcg-04` |
| --- | --- | --- | --- |
| Boot, MSGINA, wrong password rejected by LSA | pass | pass | pass |
| Licensing admission (agent status 0, activated) | pass | pass | pass |
| Explorer token/LUID/image identity, Default desktop | pass | pass | pass |
| xp/session/service/shell probes (file, HKCU, loopback, drivers, SCM, Start menu, **Luna active**, folders) | pass | pass | pass |
| `Win+L` lock, password unlock | pass | pass | pass |
| `Ctrl+Shift+Esc` Task Manager; Windows Security cancel | pass | pass | pass |
| Explorer killed → re-admission → restart → identity | pass | pass | pass |
| Logoff: notifications, no LUID processes remain, profile unloaded | pass | pass | pass |
| Re-logon to desktop | pass | pass | pass |
| Isolated network: DHCP 10.25.0.10, DNS `xp25.test`, TCP/HTTP, 6 services | 17/17 | 17/17 | 17/17 |
| Desktop Turn Off → guest-requested `SHUTDOWN` event | pass | pass | pass |
| Desktop Restart → guest `RESET` → reboot → re-logon → shutdown | pass (`wl-licensing-kvm-12`) | — | — |

TCG build 08 (`L/wl-licensing-tcg-01`) failed shell recovery with error 8;
build 10's identity hardening is what TCG-04 validates. TCG-02 and TCG-03 are
harness failures (input desynchronisation under host load; a 10 s QMP timeout)
and are frozen as such. The harness now uses 6x timing and a 30 s QMP timeout.

Earlier builds add: GINA signed-out power-off (UP-01, -06, -07), interactive
desktop shutdown (UP-08), Task Manager from Windows Security and shell
recovery (UP-06), MP lifecycle on build 08/09 (`mp-01`, `mp-02`, with one
documented harness retest). Forced QEMU termination is never counted as a
shutdown; failed experiments are frozen with `failure.json`.

## Engineering image

`W/engineering-image-02/XP25-Winlogon-Engineering.qcow2`, SHA-256
`0df7fc05b0b965941f4c488894ce200adcd44d91acf4bf28f93f7a445d30c51c`, standalone
(no backing file), read-only. `W/make-image.py` creates a staging overlay of the
verified `XP25-Components-Engineering.qcow2` (`39112bbd…0296`), checks all 22
recorded component hashes, writes only `/WINDOWS/system32/winlogon.exe` (build 10),
re-checks them, then flattens with `qemu-img convert`, `compare` and `check`; the
staging overlay is never booted. The original Winlogon is not in this image.

Independent boot proof `L/wl-engineering-proof-kvm-02`: a disposable overlay of
the standalone image (launcher re-verified every component hash, installed
nothing) passed all 18 lifecycle/regression/network gates and shut down through
the desktop with a guest-requested `SHUTDOWN` event
(`W/engineering-image-02/independent-boot-proof.json`, evidence hashes inside).
`engineering-image-01` (build 09, `aff3c2d8…494b`, also boot-proven) is retained
and marked superseded.

## Preservation

`Source/`: all 277,863 files re-hashed, manifest SHA-256
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`, unchanged
(`W/source-preservation.json`). The four frozen reference/engineering images and
the MP base (`d46fa4bf…8b8f`) are unchanged and read-only
(`W/reference-preservation.json`). The six libvirt user VM definitions and the
running `xp25-sp3` process identity are unchanged (`W/vm-preservation.json`); no
user VM was touched. The previous session's three running control guests were
paused through QMP (not shut down, disks unchanged) to free the host for TCG.

## Known gaps and defects

* **Terminal Services session state.** `qwinsta` shows the console session
  `Conn` with no user while XP25 is logged on (original: `Active`). The
  `_WinStationNotifyLogon/Logoff` handshake (token, user, `USERCONFIGW`) is not
  implemented. Consequences: Task Manager's Users tab, WTS session queries.
* **Logon-desktop theme and post-logoff edit painting.** The Themes service only
  signals sessions in Active/Connected/Disconnected state; the logon desktop is
  never themed (classic edit borders; the original's boot-time classic dialog is
  themed, `L/wl-original-classic-kvm-01`). After a logoff, MSGINA's name and
  password edits are enabled and accept input (re-logon succeeds) but do not
  paint. The original Winlogon paints them in the same classic-logon test.
* **Welcome screen.** MSGINA's status-host contract (ordinals 11, 12, 18, 22,
  27, 28) is not driven, so the classic logon dialog is used where the original
  shows the Welcome screen.
* **Fast User Switching.** The Log Off dialog offers Switch User; `WlxDisconnect`
  is unsupported and was not exercised.
* **Event sounds.** `LOGON_PLAYEVENTSOUND` is acknowledged once and not played
  (lab guests have no audio device).
* **Group Policy.** Winlogon-driven foreground/background policy processing is
  not performed. Domain logon remains unsupported.
* **Activation UX.** Reminders and the activation wizard after grace expiry are
  not implemented; expiry only denies logon (not runtime-tested: the image is activated).
* COM1 diagnostics still take the exclusive serial port briefly at session transitions.
* **Pending computer name.** The original `winlogon.exe` copies `Tcpip\Parameters\NV Hostname` (and
  `NV Domain`) into the active `Hostname`/`Domain` at startup; its binary contains these strings. The
  independent Winlogon does not, so after a rename the DNS host name stays old and the Computer Name tab
  keeps showing a pending rename. Found and worked around on 2026-10-25
  ([xp25-vm-configuration.md](xp25-vm-configuration.md)); not fixed in the Winlogon.
* The inherited native session-test executable (`build/prepare_session_tests.py`,
  `tests/guest/session_runtime.c`) last ran as `runtime-06` in the original-Winlogon
  control `L/wl-lifecycle25-control-up-02`: 79 checks, 3 failures
  (`shell_failure_real_resource_cleanup` error 1444, `private_attention_transition`,
  `native_runtime_operation`). That harness drives the coordinator from an ordinary
  process; it was not changed here and its failures remain open. The replacement
  Winlogon itself is validated by the guest matrix above.

## Reproduction

```sh
python3 build/prepare_winlogon.py --output W/build-media-NN
python3 vm/native_build_lab.py --name wl-licensing-build-NN \
  --base .work/boot-debug-20261022/userenv-rebuild-01/disk.qcow2 --media W/build-media-NN/native-winlogon.iso
bash W/build-cycle.sh NN                       # build, normal shutdown, extract, source match, PE check
python3 W/launch-native.py NAME up|mp|tcg W/production-NN-extracted/nt/xp25/winlogon/obj/i386/winlogon.exe
python3 vm/xp_lab.py L/NAME qmp cont
python3 W/lifecycle.py NAME [--slow]          # writes L/NAME/lifecycle-result.json
python3 W/desktop-power.py NAME shutdown && python3 W/finish-normal.py NAME desktop-shutdown-event.json "TRIGGER"
```

Stalls are diagnosed with `vm/capture_memory.py` (pause, registers, physical
memory, resume) and `vm/inspect_threads.py` (process/thread wait reasons, waited
object names and user-mode frames from the matching kernel map).
