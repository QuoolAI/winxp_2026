# Winlogon policy and native session contract verification

2026-10-24, `xp25-nt`, input `8e4bdba7c`.
**The independent Winlogon still cannot admit an Explorer/Luna session.**
Real key-protection initialization is now implemented, but the licensing
admission/orchestration contract remains unavailable. Production returns
error 120 and cleans up; no activation result is invented. No accepted image
is generated. This record supersedes the older policy investigation where
the newer evidence below contradicts its static findings.

Private evidence roots are `W=.work/winlogon-policy-20261024` and
`L=.work/boot-debug-20261022`. `W/start.json`, `commands.jsonl`, build-media
manifests, frozen overlays, serial logs, screenshots and matching PDBs retain
the inputs, executed commands and failures. Nothing was uploaded or pushed.

## Policy investigation and implemented initialization

The old `security.c:wl_session_policy` had no dependency calls: it set error
120, logged the unresolved contract and returned FALSE. Consequently that
error was never an observed licence denial or licensing-server failure.

The supplied **kernel binary does contain** `NtLockProductActivationKeys`.
The UP kernel map identifies `_NtLockProductActivationKeys@8` in
`ex:systime.obj` at preferred address `00616024`; its C implementation is
absent. `_ZwLockProductActivationKeys@8` is also mapped. Disassembly retains
the real protected-registry implementation and its two optional output
pointers. The older claim that there was no implementation was too broad:
there is a linked prebuilt implementation, although its C source and the
Winlogon orchestration are missing.

A disposable, unchanged original-Winlogon control based on the verified
engineering image records three actual calls, each returning NTSTATUS 0 and
opaque outputs `[3706, 0]`. Callers are `5f0f2693`, `04012ce1`, `5f0f2771`.
`L/winlogon-policy-original-kvm-01/original-policy-calls.json` retains them;
`W/kernel-activation-disassembly.log` retains the separate static evidence.
Hardware breakpoints do not patch code, return values or guest memory.
Some unrelated GetProcAddress string reads crossed inaccessible pages;
those trace errors remain recorded. This is not a complete original policy
call graph, and the COM capture does not establish a licensing-agent ABI.

`policy_native.c:wl_policy_initialize` resolves the actual ntdll export and
calls the actual kernel service in the registered Winlogon process. A failure
preserves its NTSTATUS and maps the error through `LsaNtStatusToWinError`;
startup cannot continue. Success establishes **key protection only**. Neither
output is interpreted as entitlement, activation success or shell permission.
Native UP, MP and TCG boots observed status 0 and the same two output values.

The documented XP [Windows Product Activation provider](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/licwmiprov/windows-product-activation-provider)
exposes a read-only status observation through
[`Win32_WindowsProductActivation`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/licwmiprov/win32-windowsproductactivation).
The separate `tests/guest/policy_observe.vbs` queries only ActivationRequired,
RemainingGracePeriod and RemainingEvaluationPeriod in `root\cimv2`. Under
the original authenticated engineering host it returns `0`, `2147483647`,
`2147483647`, respectively, and exits 0. No Activate/SetProductKey method is
called and no licensing record is read out or rewritten.

This observation does not establish Winlogon's complete channel/OEM,
initialization, integrity, expiry, error or recovery decisions. The original
Winlogon source and private licensing headers remain absent; the OOBE COM
caller is not a replacement for that contract. **The exact remaining blocker
is an independently established licensing-preserving admission implementation.**
It is not missing `NtLockProductActivationKeys` machine code or a demonstrated
failure of the supplied guest's licence state.

## Shared coordinator and production boundary

`policy.h` separates unavailable, denied and allowed decisions, versioned
evidence and an actual error. `policy.c` admits only an explicit allow with
all required evidence and no error. Malformed/incomplete results fail closed;
denials preserve their error. The native provider can currently establish
only key protection, so it deliberately supplies Unavailable/error 120.

`session.c` retains the working UserEnv/profile/hive/environment and token
checks. It binds one static native driver to the portable coordinator in
`session_engine.c`. The coordinator orders profile preparation, policy,
environment copying, secure desktop and ACL setup, Logon/StartShell
notifications, GINA shell activation, actual Explorer identity validation,
PostShell and Default desktop switching. It advances to Interactive only
after all required operations succeed. The original
[Winlogon/GINA architecture](https://learn.microsoft.com/en-us/windows/win32/secauthn/interaction-between-winlogon-and-gina)
is retained.

The environment copy transfers to the GINA adapter on activation entry,
including failure. The host UserEnv allocation remains separately owned.
An untransferred copy is freed exactly once during rollback. A partially
protected or started session must first quiesce user processes and revoke
desktop/station grants; cleanup failure retains ownership and enters Failed.

Lock/unlock validate the existing token and require GINA unlock authorization.
Logoff invokes normal USER/CSRSS end-session processing under the authenticated
LUID, verifies no matching processes remain, removes user desktop/station
access, waits for user notification jobs, releases GINA references, destroys
the environment, unloads the profile and finally closes the token. Only then
does the generation advance and another login become possible. The supplied
USER code checks the impersonated thread LUID and registered Winlogon caller;
the implementation uses that path instead of terminating arbitrary processes.
Native post-shell logoff remains unexecuted because admission is blocked.

Power requests run Shutdown notifications synchronously, call GINA shutdown,
allow USER/CSRSS system end-session processing through ExitWindowsEx and then
call the real NtShutdownSystem. USER's Winlogon-caller completion bit prevents
recursive handling of the host's own end-session notification. The persistent
machine-lifetime CSC Startup job is still retained during user cleanup.

There is no registry, environment, command-line or exported test-mode selector.
Production sources define `XP25_PRODUCTION_WINLOGON`; combining this with
`XP25_SESSION_TEST` is a preprocessing error. Explicit doubles live only in
the separate test executable. Production build media include neither the
test sources nor its entry point; the test-only output marker is absent from
the production PE. Host negative compilation verifies the guard.

## Executed tests and fresh native builds

The shared coordinator runs **31 scenarios / 528 assertions / zero failures**
on the host, under ASan/UBSan, and in an ordinary process inside the original
authenticated XP25 guest. These cover complete/incomplete/denied policy,
profile initialization and partial failure, mandatory token checks, invocation
of the shell adapter, environment transfer and lifetime, shell failure,
identity rejection, desktop failure/restoration, notifications, locking,
GINA-authorized unlocking, logoff, repeated login, power requests and fatal
cleanup failure. Test-double success is never counted as native shell success.
The full existing host suite passes **40 tests**.

The separate native test also checks the actual existing Explorer/caller logon
identity, visible taskbar, profile directory, real UserEnv allocation/release,
unchanged caller environment, and file/HKCU round trips. Every check passes.
The existing native standard, session, networking, service and shell probes
then exit 0 in that control. The standard probe still reports four deliberately
incomplete observations; these are not promoted to supported features.
The shell probe verifies the source Explorer checksum, Start menu, active Luna,
folder contents and taskbar survival. Both original-host controls shut down
normally. These are original-Winlogon controls, **not replacement acceptance**.

The established native build infrastructure was actually executed, without
Wine. The first production build catches C4706/C2220 in the new coordinator;
moving assignment out of the condition fixes it. Separate test builds catch
the old compiler's constant-condition macro warning, main calling convention
and possibly-uninitialized token statistics. Each failed log is retained;
the test harness is corrected without disabling `/W4 /WX`.

| Artifact | Fresh production Winlogon | Separate native session test |
| --- | --- | --- |
| Native experiment | `L/winlogon-policy-build-02` | `L/winlogon-policy-test-build-03` |
| Exact media | `W/build-media-03` | `W/test-build-media-05` |
| Compile/link | 14 source/resource files, one executable, exit 0 | 7 files, one executable, exit 0 |
| PE | i386 PE32, GUI, image version 5.1 | i386 PE32, console, native XP dependencies |
| Bytes | 34,816 | 13,824 |
| SHA-256 | `120a9ddebcf610a060a8aac6d42ee01f9308e1deb8b34560f26e8d230b7030d1` | `8dcd02a7d0112d169e21722fc5722b37c30fb3b21a2f7724e79aaac7fcc8b7ae` |
| Production checksum | `0x1091e`, independently recomputed | Independently valid |
| Direct imports against engineering DLLs | All resolve | All resolve |

Build hosts use fresh overlays of `L/userenv-rebuild-01/disk.qcow2` and shut
down normally. Extracted native sources match the media/current source;
the production PDB's NB10 timestamp/age matches the new executable. The host
MSF7-only reader rejects this old MSF2 PDB; the retained private MSF2 reader
extracts matching symbols. Neither that diagnostic rejection nor an early
UI input sent before boot completed is presented as a compiler/runtime pass.

Reproduction uses the existing tools, for example:

```sh
python3 build/prepare_winlogon.py --output .work/NEW-PRODUCTION-MEDIA
python3 build/prepare_session_tests.py --output .work/NEW-TEST-MEDIA
python3 vm/native_build_lab.py --name NEW-BUILD --base .work/boot-debug-20261022/userenv-rebuild-01/disk.qcow2 --media .work/NEW-PRODUCTION-MEDIA/native-winlogon.iso
# In the native guest: D:\build.cmd C:\xpout\NEW-RESULT
python3 -m unittest discover -s tests -v
```

`W/commands.jsonl` supplies the exact executed paths, extraction, installation,
debugger and QMP commands; fresh names are required rather than overwriting
experiments. `build/prepare_session_tests.py` makes a distinct console target
using the established native build driver, with no production-driver override.

## Replacement guest results

UP KVM and TCG overlays use the latest verified standalone engineering image,
SHA-256 `39112bbd46f89308180d651a94826808dee3a6acdcc18309b9af7c6d90340296`.
MP KVM uses its verified native-components MP checkpoint
`L/shell-userenv-combined-kvm-mp-02/disk.qcow2`, SHA-256
`d46fa4bf039d8c08990d5b019600f99cc2b593b83089c5ccda34847016573b8f`.
All inspected core components match; the MP kernel/HAL match their actual
source-built MP outputs. Only the new Winlogon is explicitly installed in
each fresh overlay, with offline before/after hashes and original recovery
bytes preserved. Original recovery SHA-256 is
`7cd68891d5f65be3f045b1c4314d4cfba030bc96ece71d240ad1a1404f1325ea`.

| Gate | KVM 1 vCPU | KVM 2 vCPUs | TCG 1 vCPU |
| --- | --- | --- | --- |
| Fresh executable / source kernel / MSGINA UI | Observed | Observed, native MP pair | Observed |
| Actual key-protection initialization | NTSTATUS 0 | NTSTATUS 0 | NTSTATUS 0 |
| Incorrect credentials | LSA `c000006d`, substatus 0 | LSA `c000006d`, substatus 0 | GINA rejection UI |
| Correct credentials / token / SID hive / environment | Observed | Observed | LSA 0/0 and observed |
| Repeated initialization and profile cleanup | Two cycles | Two before restart, one after | Two cycles |
| Live cleared token/profile/environment/GINA ownership | Captured | Captured | Captured |
| Policy admission / GINA shell / Explorer / Default | Blocked, local 120 | Blocked, local 120 | Blocked, local 120 |
| GINA-requested signed-out power-off | Guest shutdown event | Guest shutdown event | Guest shutdown event |
| GINA-requested restart | Not run | Guest reset; MSGINA returns | Not run |
| Desktop lock/unlock/logoff, user security, desktop regressions | Not reached | Not reached | Not reached |

Experiments are `L/winlogon-policy-native-{kvm-01,kvm-mp-01,tcg-01}`.
UP actual authentication succeeds with LUID `c4d7`, then retry `cd8a`; MP
records distinct successful token LUIDs in serial output; TCG records `c077`
and retry `cd79`. Correct token type is Primary (1), session 0. At the UP/TCG
policy breakpoint, phase is StartingShell, token/profile owned, environment
non-null, shell not owned, and live Winlogon checksum is `0x1091e`.
The raw EBP frames include `wl_session_policy` at `01006b4a`, adapter return
`01005e5a`, coordinator return `010065f2`, and `wl_session_start` return
`010061d7`. Nearest-public-symbol labels on private functions are approximate;
the raw frames are retained rather than claiming complete private symbols.
The GINA-shell entry breakpoint is not reached. MP's partial debugger capture
misses successful calls; its separate serial and direct readback are retained
without claiming a complete LSA trace.

After the error is continued, the environment and hive are released and the
token and GINA/MPR pointers are zero. Direct process inspection finds only
the fresh Winlogon and no Explorer/userinit. Error screenshots remain error
screenshots. Guest-requested shutdown events, not QEMU termination, establish
the limited signed-out power-off results; these do not establish post-shell
logoff, service-shutdown regression or desktop acceptance.

The first MP power-off attempt after restart sent input before the expected
shutdown dialog existed. It performed another valid login/rollback and timed
out waiting for a shutdown event; it is retained as a failed UI experiment.
The retry first verifies the actual dialog and Shut down selection, then records
the real guest-shutdown event. Earlier extraction attempts also request an
absent `buildfre.err`; the authoritative native.log files were extracted and
contain the failed builds, with the missing-path errors preserved separately.

## Remaining limits and preservation

Licensing admission must be implemented from an established contract before
the guarded native shell path can be tested. Normal desktop logoff/relogin,
post-shell failure cleanup, lock/unlock, hostile-client secure-desktop tests,
all post-shell notifications, shell crash detection/recovery and the complete
replacement application/network/service matrix remain incomplete. Shell
crash recovery is not implemented by the new coordinator. Domain profiles,
GPO/provider orchestration and volatile-environment persistence remain gaps.
The critical-process failure loop remains intact; no security error is muted.
SMSS critical-process termination behavior was not fault-injected in this run.

All 277,863 `Source/` files retain the original 6,322,952,743-byte inventory,
manifest SHA-256 `9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
Earlier engineering/reference image hashes are unchanged. Six persistent user
VM definitions match the prior record; live versus inactive XML explains the
running XP VM's runtime-only fields. A previously absent old PID remains
absent, rather than being claimed preserved. No user VM operation was issued.
All test/build guests are private overlays and the original recovery bytes
remain retained. No new accepted engineering image is made.
