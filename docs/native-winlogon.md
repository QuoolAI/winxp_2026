# Milestone 5: independent Winlogon development

2026-10-24, branch `xp25-nt`, continued from `ed4f09d2b`.
**Experimental implementation; milestone acceptance has not been achieved.**
The accepted engineering image still requires the original Microsoft Winlogon.
No reference image or interactive libvirt VM is an integration target.

## Profile preparation continuation, 2026-10-24

Continued directly from `46d081035`; the existing initialization, LSASS, GINA
and authentication implementation remains in place. `session.c` now implements
local-account profile preparation and failure cleanup. It verifies the token's
resolved account against GINA's identity, invokes the existing UserEnv profile
manager, forwards the GINA profile metadata, calls `LoadUserProfileW` and checks
the actual registry-handle name against `\\REGISTRY\\USER\\<token SID>`.
It creates a separate user environment, sets its console-session name and checks
USERNAME, USERDOMAIN and USERPROFILE against the authenticated account and
UserEnv's actual profile directory. It does not change the SYSTEM process's
environment or launch a SYSTEM shell.

The [profile API contract](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew)
requires the returned hive handle to be released through `UnloadUserProfile`;
the new cleanup follows that ownership rule. GINA releases its references first,
then the host destroys its environment and unloads the profile before closing
the token. Cleanup failures retain ownership and stop on the secure desktop.
The [environment API](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createenvironmentblock)
is called after loading the profile, with inheritance disabled. Bounded UTF-16
inspection rejects missing terminators, malformed entries and duplicate target
variables while preserving Unicode values and drive-directory entries.

`W2=.work/winlogon-session-20261024` retains this continuation's inputs, build
media, logs, manifests and experiments. Native build 01 rejected a potentially
uninitialized SID-use variable under `/W4 /WX`. Build 02 compiled, but actual
boot testing returned error 127: `InitializeUserProfile` is a **NONAME** export,
not a named API. The verified SP3 adapter maps ordinal **117** to original SP1
ordinal **118**. Build 03 uses that established contract; no guessed ordinal
fallback or swallowed failure was added.

Build 03 is 26,624 bytes, i386, GUI subsystem, PE checksum `0x135fb`, SHA-256
`8a90fca41f1d21454ddb224276b33afdeab60f1b39d3f5deb6bd5057a4e8d7a7`.
The following are actual boot-replacement observations, with the existing native
kernel/GINA/UserEnv retained:

| Profile-stage observation | KVM, one vCPU | KVM, two vCPUs | TCG |
| --- | --- | --- | --- |
| GINA authentication and token/account matching | Observed | Observed | Observed |
| Fresh profile created; loaded hive matches authenticated token SID | Observed | Observed | Observed |
| User environment and console-session variables verified | Observed | Observed | Observed |
| Environment release and successful profile-unload API after rejection | Observed | Observed | Observed |
| Rollback reaches signed-out with token closed | Observed | Observed | Observed |
| Shell activation and completed Explorer/Luna login | Not reached | Not reached | Not reached |
| Normal logoff, shutdown/restart and full replacement regression | Not reached | Not reached | Not reached |

The runs are `L/winlogon-session-native-kvm-01`,
`L/winlogon-session-native-kvm-mp-01` and
`L/winlogon-session-native-tcg-01`. Their common frozen parent,
`L/winlogon-session-fixture-kvm-01/disk.qcow2` (SHA-256
`f1ed3d30cbb7269d0e6c43990359223db794eb67d9f277d614fd8984943e1e3c`),
adds only a disposable local test account to the previously verified stack and
retains original Winlogon. Two full existing suites and real service/guest
shutdown pass in that control. The account's profile hive is absent there and
is present in offline readback from each replacement child. Original and
replacement Winlogon bytes, serial/on-disk logs and matching UP/MP kernel
identities are retained. This verifies preparation and cleanup API results;
it does not establish hostile-user security equivalence or complete logoff.

Reproduce with the existing native build driver and frozen prepared build VM,
using `W2/build-media-03`. The fixture recipe and exact UI commands are in
`W2/prepare-session-fixture.cmd`, `W2/submit-fixture.py` and the guest journals.
The fixture's `net user` command prompted about its long test password; the
recorded `Y` input completed creation. No existing XP25 password changed.
The replacement matrix uses the normal `network_lab.py` one-component option
with the fixture parent and build-03 binary, adding `--cpus 2` or `--accel tcg`.
There is no activation override or shell-enabling test switch.

**The remaining startup error is `activation_policy_contract_unresolved`, 120,
after profile/environment preparation and before shell activation.** Original
activation enforcement has not been retired, patched or replaced with success
results. A verified licensing-preserving orchestration interface remains
unavailable. GPO/GINA volatile-environment integration, network-provider scripts,
GINA shell activation, userinit/Explorer and the subsequent session lifecycle
remain unfinished. Their [shell callback contract](https://learn.microsoft.com/en-us/windows/win32/api/winwlx/nf-winwlx-wlxactivateusershell)
is documented, but compilation or profile preparation cannot stand in for its
runtime acceptance. No new standalone engineering image is produced. The
portable environment test adds thirteen cases; all **38** host checks pass.
The prior engineering image, Source and user VMs remain unchanged.

## Implemented source

`components/winlogon/` contains independently authored native C, an NT build
description and a version resource. It does not link a ReactOS, Wine, Linux or
modern Windows runtime. Surrounding supplied NT code and public interfaces were
examined; this is not a claim of a formally separated clean-room process.

* `state.c`: explicit initialization, authentication, profile, shell, security
  dialog, lock, unlock, logoff, rollback and power states. Token/profile/shell
  ownership and operation evidence gate transitions. These are model states;
  several native operations below are still unimplemented.
* `main.c` and `security.c`: NT 5.1/x86/2600/session-0 checks, SYSTEM and enabled
  privilege checks, actual USER/CSRSS logon-process registration, protected
  WinSta0/Winlogon/Default objects, logon-notify window, trusted SAS hotkey,
  LSASS/SCM startup, actual SAM-ready event and trusted LSA registration.
* `bootkey.c`: original native LPC server for the existing LSASS startup-key
  client. Only stored SYSKEY mode is implemented. The server reads existing
  protected registry metadata; it does not change it. SYSTEM-only port ACL,
  recorded LSASS PID, client impersonation/SYSTEM/session checks and actual
  cipher-validation results gate the exchange. Buffers are wiped and secrets
  are not logged. These checks still need dedicated hostile-client testing.
* `gina.c`: typed WLX 1.4 dispatch, original MSGINA negotiation/initialization,
  modal dialogs, SAS delivery, authentication result ownership, primary-token,
  authentication-LUID, session and logon-SID validation. SYSTEM is rejected as
  the user token. Denial and interrupted authentication cannot start a shell.
* `notify.c`: documented registry-driven callbacks, checked strings/paths,
  asynchronous worker ownership, token duplication, optional impersonation
  and explicit callback failures. Startup callbacks are exercised; other
  lifecycle notifications have no accepted runtime coverage.
* `session.c`: local profile/hive/environment preparation and failure cleanup,
  as described above. The remaining activation-policy boundary rejects shell
  startup. Policy, userinit/Explorer and the full session/power lifecycle remain
  unimplemented; no unauthenticated shell is permitted.

The native compiler runs with `/W4 /WX`. The initial core build 09 compiles ten files, links one
executable and binplaces it successfully. Its i386 PE is 23,552 bytes, subsystem
Windows GUI, image version 5.1, checksum `0xb103`, SHA-256
`9d3dc1b87b79c3121bafbfced1bcc9395169106fe3bece0531abcc0d08181be9`.
Static PE inspection is separate from authentication and desktop acceptance.

## Contracts and independent implementation boundary

Microsoft's [GINA interaction contract](https://learn.microsoft.com/en-us/windows/win32/secauthn/interaction-between-winlogon-and-gina)
and [WLX 1.4 dispatch structure](https://learn.microsoft.com/en-us/windows/win32/api/winwlx/ns-winwlx-wlx_dispatch_version_1_4)
define the public host interface. The supplied `public/sdk/inc/winwlx.h` pins
the x86 dispatch size at 108 bytes and notification structure at 32 bytes.
The host owns the token and allocations returned by
[WlxLoggedOutSAS](https://learn.microsoft.com/en-us/windows/win32/api/winwlx/nf-winwlx-wlxloggedoutsas).
No credential buffer is written to evidence logs.

Additional supplied contracts inspected include SMSS startup/monitoring,
CSRSS registration, Win32k logon-process and SAS privilege checks, original
MSGINA authentication, UserEnv profile/policy initialization, SCM shutdown,
native LSA initialization, NT LPC headers and the Wx client protocol.
Private source-path/hash references are in `W/research.json`.

ReactOS Winlogon's [build description](https://github.com/reactos/reactos/blob/master/base/system/winlogon/CMakeLists.txt)
and [header/license](https://github.com/reactos/reactos/blob/master/base/system/winlogon/winlogon.h)
were examined for architecture and dependency comparison. The retained
One-Core-API checkout `9eb3c31de9460c1ccce3f6a10c9c4a704f032514` uses a
ReactOS-derived host and Wine-linked support. Neither implementation was copied
or linked. [Wine's Unix runtime architecture](https://github.com/wine-mirror/wine)
does not meet this project's native NT runtime requirement. No replacement
upstream implementation or new runtime was imported.

## Debugging evidence

Here `W=.work/winlogon-m5-20261024` and
`L=.work/boot-debug-20261022`. All generated artifacts remain private.

1. Build 01 failed on genuine SDK macro/access-mask and warning errors. Build
   02 linked but failed binplace without a version resource. Build 04 rejected
   potentially uninitialized notification flags. Logs are retained; none is
   called a successful native build.
2. Build 03 booted as the replacement but failed enabling privileges with RPC
   error 1722: `LookupPrivilegeValue` requires LSASS before LSASS exists. The
   correction uses the verified NT 5.1 privilege LUID constants and checks real
   `AdjustTokenPrivileges` results; it does not invent privilege success.
3. Build 05 registered USER and created secure desktops under KVM, MP KVM and
   TCG. LSASS raised hard error `0xd0000034` (object-name failure with hard-error
   flag). Read-only kernel hardware breakpoints captured frames, instruction
   context, loaded-module identities and object operations. The decisive final
   operation was `NtConnectPort("\\Security\\WxApiPort")`. The working image
   contains source-built LSASRV and Secur32; this is their startup protocol.
   `L/winlogon-lsa-trace-03/lsa-hard-error.json` records the failure. The first,
   overly broad trace was interrupted before capture and is marked incomplete.
4. Build 06 supplied the endpoint but used a 60-byte record. The NT SDK's
   double-aligned `PORT_MESSAGE` makes the actual outer record **64 bytes**,
   with 40 data bytes. Disassembly of the installed native LSASRV confirms
   writes of `0x28` and `0x40` before `NtRequestWaitReplyPort`. Build 07 corrects
   the layout and LSASS reports actual successful cipher authentication. The
   three build-06 guests are rejected. Dismissing a fatal popup in the UP run
   subsequently produced STOP 8E; this is retained as failure evidence.
5. Build 07 reached original MSGINA's graphical login. A wrong password was
   visibly rejected, but the existing empty-password account returned
   `STATUS_ACCOUNT_RESTRICTION`. Read-only API entry/return tracing established
   local `Interactive` type 2 and status/substatus `0xc000006e`. Console ID was
   already zero; the initial remote-logon hypothesis was disproved.
6. A separate original-Winlogon control captured successful
   `MsV1_0SetProcessOption`, mask 3, disable=false, status/protocol-status zero.
   Supplied MSV1_0 code associates options with the calling PID. Build 09 asks
   only for the existing local-console blank-password option (mask 1), checks
   real API/protocol errors and console ownership, and leaves the separate
   administrator-lockout exception unrequested. No account password or machine
   authentication policy changes. Authentication still goes through original
   GINA/LSA and the returned token is checked.
7. Build 08 added bounded SAM readiness and serialized logging. An unnecessary
   `_WinStationWaitForConnect` call on an already active console returned RPC
   error 1702. Build 09 accepts actual matching console ownership first; it
   does not write shared kernel data or fabricate a console identity.

`W/startup-key-contract.json`, `wx-message-length-proof.txt`,
`authentication-contract.json`, build-media manifests, native compiler logs
and the individual `L/winlogon-*` journals retain the exact evidence. Early
build-03 probe logs failed to escape DLL-path backslashes; later logging fixes
JSON escaping, preserves last-error and serializes concurrent writers.

## Testing and limitations

The portable C89 state test executes **320,991 assertions** over behavioral
sequences and all enumerated phase/event/evidence combinations. Seven synthetic
startup-key decoder cases cover valid placement and malformed input; no real
registry key is a fixture. The initial core checkpoint passed 37 host checks;
the profile continuation above raises that count to 38. These tests do not
establish native authentication security.

`L/winlogon-core-control-kvm-01` runs build-03 `--self-test` and `--probe` in
ordinary processes while retaining original Winlogon. Two complete existing
regression suites, service shutdown and actual guest shutdown pass. This is a
control, **not** a replacement login or Milestone 5 acceptance.

The current replacement matrix and exact remaining runtime failure are recorded
in `W/runtime-matrix.json` and `W/component-manifest.json`.

| Build 09 gate | One-vCPU KVM | Two-vCPU KVM | TCG |
| --- | --- | --- | --- |
| Secure objects, real startup-key validation, SAM and trusted LSA | Observed | Observed | Observed |
| Original MSGINA 1.4, graphical login, wrong-password rejection | Observed | Observed | Observed |
| SAS interruption, NONE return and authentication re-entry | Observed | Observed | Observed |
| Valid GINA result and token checks reach profile state | Observed | Observed | Observed |
| Actual LSA `Interactive=2`, status/substatus zero capture | Captured | Incomplete | Captured |
| Session startup | Error 120 | Error 120 | Error 120 |

The three runs are respectively `L/winlogon-native-kvm-06`,
`L/winlogon-native-kvm-mp-03` and `L/winlogon-native-tcg-03`. KVM/TCG negative
API captures return `0xc000006d`; MP rejection is a reviewed real GINA error
dialog. The MP API tracer initially assumed CPU-0 memory context and failed;
its failed logs are retained rather than reported as a successful API capture.
Mapped-module records in the successful captures identify the actual new
Winlogon checksum `0xb103`, original-source MSGINA/Secur32 and adapted UserEnv.
Offline readback verifies the exact new Winlogon and both original recovery
copies in all three guests. On-disk and serial host logs match byte for byte.
Matching UP/MP source-kernel checksums pass; no Explorer process is present at
the stopped boundary. No exception return or authentication result is patched.

No replacement guest has an accepted Explorer/Luna
desktop, lock/unlock cycle, logoff/relogin, normal service/guest shutdown,
restart, full application/network regression or standalone engineering image.
Failed experimental guests are stopped through host QMP and explicitly marked
`normal_shutdown=false`; that stop is never counted as a guest shutdown test.

Unsupported features include complete interactive session/GPO/shell operations,
GINA volatile-environment and network-provider integration;
complete licensing/activation preservation; logoff/power/service coordination;
shell recovery; secure screensaver/idle policy; password/network-provider change
notifications; custom desktops/return-desktop and legacy shell-protection
callbacks; smart cards (including `WLX_OPTION_SMART_CARD_PRESENT`); domain,
roaming/cross-forest profiles; RDP/TS/FUS and console switching; migration and
complete process-critical/fatal recovery behavior. Original notifications beyond
Startup and secure-desktop denial by a logged-on hostile user remain unverified.
The prototype displays classic MSGINA UI rather than the previously branded
Welcome screen; prior branding/UI equivalence is not accepted.

The installed Winlogon's inspected imports/public symbols include integrated
WPA policy, OEMBIOS handling, the WPA global mutex and
`NtLockProductActivationKeys`. The Winlogon source providing this orchestration
is missing. Its complete semantics have not been independently established.
The replacement must not omit that policy and call the omission permission to
start Explorer. `session.c` now prepares the local profile, then stops before
shell startup and releases its profile/environment resources. An
accepted licensing-preserving implementation is required along with the actual
Stage C lifecycle code and positive/negative security/regression tests. No
activation registry state, activation result or licensing check is patched.

## Build and isolated reproduction

Use fresh output and experiment names. Build media contains only the new XP25
sources and driver. The native VM copies them to disposable
`C:\nt\xp25\winlogon`; the host `Source/` remains immutable.

```sh
python3 build/prepare_winlogon.py --output .work/winlogon-m5-20261024/build-media-NEW
python3 vm/native_build_lab.py --name winlogon-native-build-NEW \
  --base .work/boot-debug-20261022/userenv-rebuild-01/disk.qcow2 \
  --media .work/winlogon-m5-20261024/build-media-NEW/native-winlogon.iso
# After the private build desktop is ready:
python3 vm/xp_lab.py .work/boot-debug-20261022/winlogon-native-build-NEW run \
  'cmd /c D:\build.cmd C:\xpout\winlogon-NEW' --settle-seconds 3
# Require XP25_WINLOGON_BUILD_EXIT=0, then actual guest shutdown and freeze:
python3 vm/xp_lab.py .work/boot-debug-20261022/winlogon-native-build-NEW shutdown
python3 vm/xp_lab.py .work/boot-debug-20261022/winlogon-native-build-NEW finish
python3 vm/read_guest.py \
  .work/boot-debug-20261022/winlogon-native-build-NEW/disk.qcow2 \
  .work/winlogon-m5-20261024/build-NEW-extracted \
  /nt/xp25/winlogon/obj/i386/winlogon.exe \
  /nt/xp25/winlogon/obj/i386/winlogon.pdb /xpout/winlogon-NEW/native.log
```

Run `vm/network_lab.py` with the frozen verified
`L/shell-userenv-combined-kvm-01/disk.qcow2`, existing helper/network/standard
probes and exactly one `--component /WINDOWS/system32/winlogon.exe BINARY`.
Each experiment's `inputs.json` and `qemu-command.json` record the complete
arguments and hashes. Use `--cpus 2` for the matching native MP kernel/HAL and
`--accel tcg` for TCG; pause for a read-only debugger when needed. Never point
these operations at libvirt user disks. `vm/capture_logon_boot.py` reproduces
the LSASS object/hard-error trace with the matching kernel map and leaves the
guest paused. The test wrappers do not promote a compiled binary to acceptance.

## Recovery and preservation

Every replacement records original Winlogon SHA-256
`7cd68891d5f65be3f045b1c4314d4cfba030bc96ece71d240ad1a1404f1325ea`
in its host recovery copy and guest `C:\xp25\recovery-winlogon.exe`.
Boot-critical failures can leave NTFS unclean: the first attempted offline
write failed and was retained; no journal was forced or repaired in place.
`vm/restore_winlogon.py` instead verifies the rejected experiment, original
backup and pre-experiment parent, then creates a **new child of that verified
parent**, validates its original Winlogon and retains the recovery copy.
All failed-experiment writes are rolled back; the failed disk remains evidence.

```sh
python3 vm/restore_winlogon.py \
  --experiment .work/boot-debug-20261022/winlogon-bootstrap-kvm-01 \
  --output .work/winlogon-m5-20261024/recovery-NEW
```

`W/recovery-02` was booted as `L/winlogon-recovery-kvm-01`. Two full regression
suites, native Explorer/UserEnv/GINA identity, Notepad readback, service shutdown
and actual normal guest shutdown pass. Both active and recovery Winlogon are
the exact original bytes. This proves rollback recovery, not independent-host
acceptance.

The 277,863-file source inventory remains hash-identical:
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
The previously accepted standalone image remains
`E/engineering-image-02/XP25-Components-Engineering.qcow2`, where
`E=.work/native-shell-userenv-20261024`, SHA-256
`39112bbd46f89308180d651a94826808dee3a6acdcc18309b9af7c6d90340296`.
It has not been replaced by an experimental Winlogon image. Final source,
reference-image and existing-VM preservation checks are retained under `W/`.
