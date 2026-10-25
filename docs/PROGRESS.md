# Development progress

## Current checkpoint

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
Ubuntu host. Native SCM/Winreg RPC stubs and headers were generated in build
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

Installed the user-supplied ISO on a new 32 GiB disk using QEMU 8.2.2/KVM,
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
