# Source-kernel boot investigation

This investigation uses the installed SP3 guest as a runtime/build host for the
NT 5.1.2600.1106 x86 reference. The source kernel reaches graphical login under
KVM and TCG; authentication and the desktop remain incomplete.
Private media, binaries, dumps and logs remain in
`.work/boot-debug-20261022/`; no proprietary artifacts were published.

## Preserved reference and isolated execution

System libvirt domain `xp25-sp3` has the disk-and-memory snapshot
`xp25-before-apic-debug-20261022`. Experiments use new qcow2 overlays of the frozen
`matched-hal-preboot.qcow2` checkpoint. The boot menu in each test clone selects
the experimental entry automatically. The working reference installation is not
used for test writes.

Per-run `qemu-command.json`, `journal.jsonl`, `checkpoint.json`, debugger logs,
screenshots and input hashes record execution. `matrix.py` uses an exclusive
lock and refuses to relaunch a run with an existing QEMU PID. Interrupted live
experiments require reconciliation. Every test result explicitly leaves the
desktop milestone unverified.

## APIC failure and correction

The original live failure is `KfLowerIrql`, HAL RVA `0x23b1`, corresponding to
`base/hals/halmps/i386/mpirql.asm:347`. It writes TPR `0x3d`, reads `0x30`, then
executes `int 3`. This produces `0x8e`, exception `0x80000003`. The captured stack
is `KfLowerIrql` → `KiInitializeKernel+0x199` → `KiSystemStartup+0x2c4`.
The requested Windows IRQL is APC_LEVEL (1); the APIC priority class is 3.
CPU registers, the trap/stack and APIC state are retained in
`kvm-capture/gdb.log` and the earlier native-build evidence.

The host is an AMD Ryzen 5 5600X with Linux KVM/SVM. Its priority synchronization
uses the four-bit virtual TPR/CR8 class. The observed truncation is consistent
with this implementation path.
QEMU VAPIC also rewrites TPR accesses, but disabling VAPIC still reproduces the
failure. Split IRQ chip does not resolve it; this host rejects userspace APIC.
Primary implementation references:
[KVM SVM synchronization](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/svm/svm.c),
[KVM APIC/CR8 conversion](https://github.com/torvalds/linux/blob/v6.8/arch/x86/kvm/lapic.c),
[QEMU VAPIC patching](https://github.com/qemu/qemu/blob/v8.2.2/hw/i386/kvmvapic.c).

The correction verifies all TPR bits except the low priority sub-class nibble.
It retains the APIC read used for serialization. Fast-mutex APC_LEVEL guards
compare the same priority class. The shared `CHECKTPR` macro preserves its input
registers. Ownership checks, invalid IRQL checks and assertion traps remain.
This is a compatibility experiment for the recorded virtual hardware, not a
claim of validation on physical APIC hardware.

`build/apply_boot_compat.py` emits patched copies and before/after hashes under
`.work/`; it refuses other output locations. The six affected reference paths
are `base/hals/halmps/i386/mpirql.asm`, `mpspin.asm`,
`base/hals/inc/ntapic.inc`, `base/ntos/ke/i386/misc.c` and
`base/ntos/ps/psinit.c` and `windows/core/kmode/i386/services.stb`. Original
notices remain in the copies.

The final HAL revision passes early initialization in all seven recorded
configurations: KVM qemu32 UP, KVM host UP, KVM qemu32 two CPUs with MP HAL/kernel,
TCG qemu32 UP, TCG Pentium III UP, TCG qemu32 two CPUs with MP HAL/kernel, and
TCG without CPU APIC using the ACPI PIC HAL. All subsequently stop at the SP3
GUI dependency failure. This does not establish SMP application compatibility.
See each `matrix2-*/result.json` and `gdb.log`.

A separate negative test deliberately supplies class `0x40` to the checked
fast-mutex guard. It still raises `IRQL_NOT_GREATER_OR_EQUAL` (`0x9`). Evidence:
`regression-wrong-irql/`, including `irql_guard_rejected_bad_class: true`.
An earlier MP experiment used the UP map before the MP map was available; its
result is marked `debugger_breakpoint_mismatch` and is not boot evidence.

## SP1/SP3 component compatibility

The previous NTFS and checked/free HAL mismatch failures remain preserved.
Matching native NTFS removes the SP3 NTFS import mismatch. A checked kernel must
use a matching checked HAL; the free SP3 HAL produced bugcheck `0x79`.

TCG exposed the next failure, `SESSION5_INITIALIZATION_FAILED` (`0x71`). SP1 puts
syscall instructions at shared-data offset `0x300`; SP3 ntdll expects a function
pointer there and calls instruction bytes as address `0x340fd48b`. All 284 source
native syscall numbers checked against this SP3 ntdll match. The kernel detects
the pointer ABI through ntdll exports and selects ntdll's original INT 2E entry.
It preserves the inline ABI for ntdll versions lacking those exports. It does
not alter the SYSENTER trap frame or bypass privilege checks. Direct SYSENTER,
single stepping and suspend/hibernate remain unverified for this mixed runtime.

The next Session Manager error was `0xc000003a`: `\??\C:\WINDOWS` did not exist.
SP3 MountMgr imports the absent `ObIsDosDeviceLocallyMapped`. Building and using
the matching original MountMgr restores progress past that failure.

SP3 Win32k imports absent `SeTokenIsWriteRestricted` and
`MmCommitSessionMappedView`. No security API was stubbed. A native build of
`windows/core` compiled 2,036 files and produced Win32k, although the overall
command failed at language-pack DLL debug-symbol links. Win32k's PE checksum and
all kernel/HAL imports pass inspection. It loads alongside the custom kernel;
USER/GDI initialization executes and CSRSS appears. No Winlogon or desktop has
been observed.

The live module list identifies `\WINDOWS\system32\XP25KRNL.EXE` at `0x80a02000`.
Its PE checksum `0x33f857` matches the rebuilt kernel. The loaded header has six
runtime byte differences; it is not reported as byte-identical.
Module and process evidence is in `matrix3-kvm-up/`.

CSRSS later terminates with `STATUS_INVALID_INFO_CLASS` (`0xc0000003`). The
recorded process-information trace shows set class `0x22` and query class `0x25`
returning that status. Matching native CSRSS and CSRSRV then built successfully
in `build-08`. A fresh clone with those components and matching native WinSrv,
User32 and GDI32 reports failure initializing SP3 BaseSrv (`0xc0000003`) at
`base/subsys/csr/server/srvinit.c:194`. That assertion was not ignored.

The original BaseSrv built successfully in `build-09`. Installing it in another
fresh clone reaches bugcheck `0x4c`, parameter 1 `0xc0000135`, with a hard-error
message naming WinSrv. This message comes from CSR's generic load-failure path;
it does not prove the WinSrv file is absent. `native-basesrv-loader-trace/`
records the actual `LdrLoadDll` return: `0xc0000142` (`STATUS_DLL_INIT_FAILED`).
The direct imports checked across the native GUI/CSR components, SP3 Kernel32
and SP3 ntdll resolve. `native-gui-init-trace/init-routines.log` then records SP3
Kernel32 returning FALSE for `DLL_PROCESS_ATTACH` before User32's entry routine
runs.

Native Kernel32 built successfully in `build-12`: 67 files, three libraries and
one executable, exit zero. The preceding failures preserve a missing generated
message resource and an absent output directory. The successful command creates
that directory, invokes the supplied MC on `winerror.mc`, and builds the native
NLS and LZ libraries. Kernel32's checksum and ntdll imports pass inspection.
The checked imports of the installed Winlogon, SCM, LSA, MSGINA and LogonUI
against this Kernel32 resolve; this is static evidence only.

`native-gui-access-violation/` captures the next first-chance CSRSS exception:
`0xc0000005`, EIP `0x7ffe0309`. The source GUI stub generator still calls shared
offset `0x300` as inline code, while the corrected kernel exposes SP3 ntdll's
function-pointer ABI there. Patch revision 05 changes only the two syscall
instructions in `services.stb`: `lea edx,[esp+4]`, then `int 2e`. The original
kernel service dispatcher retains its argument probing and privilege checks;
service numbers and return cleanup are unchanged.

`build-13` compiles the generated stubs and relinks User32/GDI32 successfully.
Disassembly records 270 and 366 INT 2E instructions respectively, with no old
shared-address loads. `native-int2e-init-trace/init-routines.log` records both
Kernel32 and User32 returning TRUE for process attachment. The guest then stops
with a Windows Subsystem access violation at the same shared-page location;
WinSrv still contains 22 old stubs linked from `w32umode.lib`. `build-14` relinks
WinSrv successfully, replacing all 22 with INT 2E and leaving no old shared-page
loads. `native-int2e-full-kvm` advances through USER/display initialization and
then stops with `0xc000021a`: the Windows Logon Process terminates with status
`0x80`. No login screen, authentication or Explorer is established.

The display log also records `EngBugCheckEx` missing from native Win32k.
Inspection identifies SP3 `framebuf.dll` as its importer; the inspected VGA
display DLLs have no missing Win32k imports. `build-15` compiles the matching
original Framebuf (eight files, one executable, exit zero). It loads and removes
the import failure, but `DrvEnablePDEV` reports `bInitPointer` failure. VGA
fallback and display operation remain unverified.

The termination trace shows CSRSS terminating a client with `STATUS_ABANDONED`
(`0x80`), matching its `LPC_EXCEPTION` path. `winlogon-first-exception` captures
Winlogon's actual loader exception, `0xc0000139`. The dynamic lookup trace in
`winlogon-export-lookup` identifies the missing export exactly:
`Kernel32!BaseQueryModuleData`. SP3 ntdll requests it before Winlogon's normal
imports are loaded. It is absent from the supplied SP1 source. No stub was added.

`build-16` compiles the matching original ntdll instead. Forty-one files compile
before the first missing ETW library stop; the subsequent native ETW build and
ntdll link succeed. The first generated `ntstatus` header used MC's decimal
option, which conflicts textually with the identical hexadecimal severity
constants in `netevent.h` under `/WX`. Regenerating it without that option fixes
the build without changing source headers or disabling compiler warnings.
Native ntdll has 1,411 exports, a valid checksum and no imports. Its RTL user
library was compiled during `build-03`; supplied libraries remain link inputs.

`native-ntdll-kvm` passes the dynamic Kernel32 lookup stage, then the checked
loader reports `RtlIpv6StringToAddressExW` missing. The SP3 Winsock DLL imports
that newer interface. Matching original Winsock is the next build experiment.

The initial private import parser missed rows containing an additional bound
address column. `check_logon_closure.py` now includes those rows;
`logon-closure-bound/report.json` supersedes the earlier report. The corrected
25-module scan finds no missing direct imports against SP3 ntdll and the native
Kernel32/User32/GDI32 set. Substituting native ntdll identifies the one missing
Winsock import above. This name-based scan does not validate ordinal imports,
forwarded exports, dynamic lookups or runtime ABI compatibility.

The private debugger harness previously decoded a string pointer from the
hard-error parameter vector as the status. The status is instead parameter 1
of `KeBugCheckEx`, at `ESP+8`; affected private result files now preserve the old
value and record the corrected decode. Diagnostic routine-return stops are not
classified as kernel bugchecks. Process presence and Win32k initialization do
not establish login.

## Graphical login and authentication blocker

`build-17` compiles 50 Winsock files, then stops on its missing helper library.
Building original `ws2help/ws2help/nt` compiles seven files and produces that DLL
and library; Winsock links successfully. Both DLL checksums and their checked
native ntdll dependencies pass inspection.

The next trace captures Winlogon executing `0x340fd48b`, returning to SP3 IMM32
at `0x763a45d8`. Its embedded GUI stub expects the shared pointer ABI. Matching
IMM32 already compiled in the native GUI build; its checksum and native imports
pass inspection. `native-imm-kvm` and `native-imm-tcg` then reach graphical login.

`native-imm-kvm/login-kernel-verification.json` records canonical kernel name
`ntoskrnl.exe`, full path `\\WINDOWS\\system32\\XP25KRNL.EXE`, base `0x80a02000`
and checksum `0x33f857`, matching the compiled input. Winlogon, SCM, LSASS,
service hosts and LogonUI run. Explorer has not been observed. Full disk/RAM
snapshot `source-kernel-login-error` is frozen at disk SHA-256
`caafd03bda607791ffb3d1fd63c201c30c9b879dc0919502a2bd468dc6f3d4a7`.
QMP stop/quit used for preservation is not a normal guest shutdown.

Sign-in displays “The parameter is incorrect.” The TCG trace captures
`LsaLogonUser` returning `STATUS_INVALID_INFO_CLASS` (`0xc0000003`), substatus
zero, before profile loading. `lsa-information-trace/lsa-information.jsonl`
correlates that return with LSASS `NtSetInformationToken` class 16, length 12,
returning the same status. `lsa-audit-policy-capture/audit-policy.json` captures
three zero DWORDs. This newer token audit-policy class is absent from the
baseline enumeration, which ends at `TokenSandBoxInert` (15). No auditing check
was bypassed or replaced with a success stub. Original LSA compilation is the
next experiment.

Other recorded limits remain: native Framebuf reports hardware-pointer
initialization failure, advanced IME windows report creation warnings, and SP3
`wshtcpip.dll` requires absent `RtlIpv4StringToAddressExW`. Their full functional
effects remain unverified. The authentication return has its own exact trace.

## Native build limits and hashes

A clean kernel build compiled 1,859 files but could not rebuild executive
`exinit.c` and `systime.c`, which are absent. Four supplied i386 objects are
required. Their exact hashes are in `build-04/prebuilt-inputs.json`. The final
kernel is a mixed source/prebuilt link. A complete rebuild from C/ASM and a free
variant are not established.

| Artifact | SHA-256 |
| --- | --- |
| Rebuilt checked kernel | `fcf981e59b357d789a2be8850978657e9880c23fa3cb974157bbdb7cdf70cc4d` |
| Corrected checked UP APIC HAL | `d1678e392b1331b0c7d597052471fd8649c264b325ac2b5387d984a5d3e37be3` |
| Corrected checked MP APIC HAL | `fc9df833e9d988091bce119e39f2cbb9eeb322749c46ec2aaf954a26798d920b` |
| Matching source MountMgr | `338776e980cfa36977bdc84dd159acf342d0002948ac57c5395519f1f4c939ca` |
| Matching source Win32k | `b28afb2fa1d7be5d5aa0867b17b775afdca7d24ff98f268b73f5b9dd5c4ef994` |
| Matching source CSRSS | `be8a5b9f3aa0f54fd6f5acf60e05cb7a58aa111afdfdeeae35512a39fc7fa1bf` |
| Matching source CSRSRV | `5186ac1f25b75f6ece0f91f1352874cc439c59f00c6cf818a82ec6d94372b892` |
| Matching source BaseSrv | `659ea2e7c0abe6ac1ec722acfbdf88b8efc27f1a6d73e200cc220b62610f1248` |
| Matching source Kernel32 | `d7bf3b8fae291f15e82b94a799120722125c3f6f4f21effadd6ad1255d1eec3e` |
| User32 with INT 2E stubs | `a51976ddc3ae7e12a81b188587ef39cdc0810f89d585569219908acd7dab8a58` |
| GDI32 with INT 2E stubs | `09698075402cbeaab42247124829d580a4e9535b21f443bf822c715c19c95258` |
| WinSrv with INT 2E stubs | `84df7d61bfc49c4c1c15ea7bef424f79abc03df7394fa9c7e9e875f509567f99` |
| Matching source Framebuf | `2054ab5d568bdb5cc3abf5f1b8e8259c41f6e6954776e88023a43f48b0ad998c` |
| Matching source ntdll | `f4ede1ec8f6878fc4a95f4a35010a6c85483a6ca58e34c6075becea89dcb3b20` |
| Matching source Winsock | `bd554545384e717d5b2e60b04c5f17849898d60bc1785a27b2f90fde61a02c2f` |
| Matching source Winsock helper | `9d46fea7ab72d0354d89277acc30e9543a373ee9167e007ae29067093f4dc489` |
| Matching source IMM32 | `5cf2b4a93ba13d7563653d12619750175832c940286c9c7aca964486d4328839` |

Build commands are preserved in each `build-*/build-*.cmd`, guest native logs and
serial markers. Exit zero alone was insufficient: two initial incremental
attempts did not recompile patched files. Those outputs remain recorded, and
only the later compile/link logs and changed binary hashes establish rebuilding.

## Native LSA and next shell dependency, 2026-10-23

Build-18 successfully compiles original LSA server C files, policy/common
libraries and RPC/DPAPI/Netlogon prerequisites, then links LSASRV and Secur32.
Nine staged native build scripts retain each prerequisite failure and recovery;
logs are in `build-18-extracted/xpout/lsa-01` through `lsa-09`. LSASRV SHA-256 is
`7682645776dbaf741a12e3346c3cf2c2542cfe86a98d808c44625f91d57d7731`;
Secur32 is `5975dd33df460c3a89ae35e2e09efe6e060724e70d805b8acec87e585204e6ed`.
No token-audit success stub or auditing bypass was introduced.

`matrix26.py` installs those original libraries in a fresh clone. Live kernel
inspection again verifies XP25KRNL.EXE and checksum `0x33f857`; Explorer and
user-session processes appear. Dismissing the screen saver reveals Bliss
wallpaper and repeated missing `Kernel32!DecodePointer` dialogs. Task Manager
opens with Luna styling; entering its Run field triggers the same missing API
through shell autocomplete. A single character reaches the edit field before
the modal dialog steals focus. Earlier attempted probe commands therefore did
not execute; the empty serial file is not a passing probe.

Microsoft documents EncodePointer as an XP SP2 addition with a per-process
secret, and describes XP's kernel-held state:
[API contract](https://learn.microsoft.com/en-us/previous-versions/bb432254(v=vs.85)),
[XP implementation history](https://devblogs.microsoft.com/oldnewthing/20201113-00/?p=104447).
Inspection of the user-supplied SP3 x86 ntdll shows both operations querying
process information class **36**, length four, pseudo handle -1, then XORing
the input with the returned cookie. The installed SP3 kernel requires exactly
that pseudo handle, lazily mixes system time with PRCB system-call/interrupt
counters and publishes the cookie with compare-exchange. This observation is
local binary evidence, not a claim of cryptographic entropy or a portable
undocumented API contract.

`build/apply_pointer_compat.py` generates the corresponding small x86 extension,
retains argument probing and existing EPROCESS field offsets, and checks the
new size at compile time. The cookie is not cached in user-mode globals; query
failure raises a status rather than silently returning the input pointer.
`tests/guest/pointer_probe.c` covers boundary values, concurrent round trips,
per-process separation and rejected query handles/buffers/lengths. Build-19
links successfully but omits process-allocation recompilation, so it is not a
valid boot input. A full kernel rebuild is required before runtime testing.

That full rebuild subsequently completed in build-20, including process
allocation and the four documented supplied objects. The native pointer and
session probes pass under KVM, TCG and two-vCPU KVM. A fresh KVM guest completes
interactive XP25 authentication, Explorer/Luna startup, file/registry checks,
Notepad save/reopen and normal shutdown. Its LsaLogonUser status/substatus are
zero and its logon ID matches the subsequent Explorer/user tokens. All 18
staged inputs remain after shutdown. The tracked build-21 pipeline independently
rebuilds the kernels/HALs/DLLs and boots another verified desktop.
[Final milestone evidence, hashes and reproduction](source-desktop-milestone.md)

## Checkpoint and usage-limit resumption

`build/resume_after_limit.py` watches an explicit existing session, locks one
supervisor per UUID, checkpoints atomically and waits for a server-provided reset
time. It stops on other errors, absent reset information, repeated stale resets,
or user-aborted turns. Six focused tests cover observed reset messages and
retry classification.

The actual reset attempt invoked `codex exec resume` at the recorded time, but
the open TUI retained its active thread writer and Codex rejected the resume.
The supervisor stopped. Automatic continuation of this open TUI is therefore
blocked by session ownership; the script does not remove or override that lock.
[Supported CLI session resumption](https://developers.openai.com/codex/noninteractive)
does not guarantee takeover of an open writer. See `.work/resumption/` for the
actual command and error. No successful unattended continuation is claimed.
