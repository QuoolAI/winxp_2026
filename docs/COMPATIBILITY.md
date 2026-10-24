# Compatibility matrix

The source-kernel desktop milestone passes in the recorded KVM clone, including
authentication, Explorer/Luna, file/application checks and normal shutdown.
`Not tested` means no installation, execution or
stability evidence exists; it is not a prediction of compatibility. Guest runtime
and hardware support must cite an image hash, exact version, environment and logs.

## Native Explorer and UserEnv, 2026-10-24

The [integration record](native-explorer-userenv.md) supersedes the earlier
failed variants below. All tests use disposable isolated guests with the prior
native kernel, SCM/SMSS/Regsvc/MSGINA, networking and XP25 branding preserved.

| Tested stack / gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Corrected original Explorer alone | Pass | Pass | Pass |
| Corrected original UserEnv alone | Pass | Pass | Pass |
| Both components together | Pass | Pass | Pass |
| Login/logout, lock/unlock, Explorer/Start/Luna, folder/file operations | Pass | Pass | Pass |
| Fresh profile initialization, hive/registry operations, unload/delete | Pass | Pass | Pass |
| Prior service, TCP/UDP, DHCP/DNS/isolated HTTP, Win32/MSI and branding fixtures | Pass | Pass | Pass |
| Actual mapped binaries, original recovery, Notepad readback, normal shutdown | Pass | Pass | Pass |
| Additional cold boot from standalone engineering QCOW2, two full suites and shutdown | Pass | Not repeated | Not repeated |

Explorer uses one corrected SP3 SHLWAPI provider call. UserEnv rebinds four
private ordinals; original implementation bytes remain unchanged. Three missing
implementations (CheckXForestLogon, CreateURLFile, DeleteURLFile) still use the
retained original SP3 dependency. No Winlogon patch, exception suppression or
success-returning security stub is introduced. Captured NT 5.1/x86/2600/SP3,
product/licensing identity remains unchanged. These local-account and fixture
tests do not establish domain/GPO/cross-forest/roaming-profile, every private
shell ABI, arbitrary legacy software or sustained security/stability equivalence.
Source completeness and a clean Windows Setup ISO remain separate work.

## Historical Regsvc and MSGINA extensions, 2026-10-23

The UserEnv/Explorer failures below describe preserved earlier variants; see
the 2026-10-24 matrix above for the corrected accepted artifacts.

The [extension record](native-component-extensions.md) covers individual changes
on the branded original-kernel/SCM/SMSS desktop. Working reference images and user
VMs are not integration targets.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Original Regsvc: existing 54 regressions, 21 RPC/lifecycle cases, branding and installer fixtures | Pass | Pass | Pass |
| Original Regsvc: actual mapped checksum, exact retained DLL and original recovery | Pass | Pass | Pass |
| Original Regsvc: logoff/re-entry, Explorer/Luna, Notepad and fresh service/guest shutdown | Pass | Pass | Pass |
| Subsequent original MSGINA: same full suite and four GINA/host cases | Pass | Pass | Pass |
| Original MSGINA: incorrect password rejected, existing local login succeeds, lock/unlock | Pass | Pass | Pass |
| Original MSGINA: live Winlogon-mapped DLL, secure-desktop write denial, Notepad, normal shutdown | Pass | Pass | Pass |
| UserEnv SP3 export adapter as boot replacement | Fail: Winlogon AV | Fail: Winlogon AV | Fail: Winlogon AV |
| Original Explorer shell integration | Fail: Explorer crash | Not attempted | Not attempted |

Regsvc testing uses real local named-pipe RPC with stopped-server negative
controls. SMB/remote network RPC is unverified; the first installed-SP3 control
returned error 53 for the SMB path. GINA evidence covers the existing local XP25
account, not domain, smart-card, FUS, RDP or broad security equivalence.

Original Explorer compiles successfully with original import/support libraries;
static direct/delay import presence passes but does not establish runtime private
shell ABI compatibility. The UserEnv adapter preserves original native code and
pins all SP3 ordinals, forwarding CheckXForestLogon and two unknown private bodies
to unchanged SP3 UserEnv. Fifteen ABI/profile checks pass when loaded from a
readonly CD in an own user process, separate from Winlogon. This is neither
independent implementation of those three functions nor boot compatibility.
Both rejected candidates remain excluded from the accepted engineering disk.

The packaged disk retains installed UserEnv, Explorer, Winlogon and other original
Microsoft dependencies. It is a private preinstalled engineering image containing
source/build payload, not a clean licensed installation or Windows Setup ISO.
Media/license entitlement and complete source/binary accounting remain pending.

## Interactive anniversary VM, 2026-10-23

`XP25-Anniversary` is a separate persistent `qemu:///system` domain, using a
flattened, preboot sector-identical copy of the newest branded desktop,
`brand-final-tcg-01` (reference SHA-256
`d4fa9505a725fcc670ddfd443d4179e5871ef32d27d8073e6e7e04f6b4774f85`).
The original one-vCPU qemu32/512 MiB/i440fx/IDE/VGA/RTL8139 profile boots under
KVM with the same original UP kernel/HAL, SCM/SMSS and native networking helper.
The loopback VNC console opens through virt-manager. All 54 established and 17
branding observations pass, alongside Win32/MSI fixtures and service/guest
shutdown. Sixteen critical files and captured compatibility identity values
match the reference after shutdown. Clone MAC `52:54:00:25:00:03` receives
`10.25.0.11` from the existing isolated libvirt network; DNS, TCP/UDP and isolated
HTTP pass. Only this additional DHCP reservation changes shared configuration.
Reference images and pre-existing guests remain preserved. The VM is left shut
off, ready for interactive startup; no broader compatibility claim is made.
[Exact commands, evidence and limitations](virt-manager-xp25-anniversary.md)

## XP25 resource branding, 2026-10-23

The [branding record](branding.md) covers separate disposable children of the
native SCM/SMSS checkpoint. System/About resources, Explorer, Shell32 and
LogonUI are integrated in separate stages; boot-critical components are not
replaced together. No kernel code, VERSIONINFO, ABI, licensing mechanism or OS
ProductName changes are made. One reviewed per-profile localized-name cache
entry is backed up and refreshed for the modern Start menu.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Source-kernel boot, native SCM/SMSS, Explorer/Luna | Pass | Pass | Pass |
| Existing 54 standard/pointer/session/network/service observations | Pass | Pass | Pass |
| NT 5.1/x86/2600/SP3/product type/API reporting and captured identity match control | Pass | Pass | Pass |
| Branding resources and original recovery files retained | Pass | Pass | Pass |
| Logoff, branded chooser and successful reauthentication | Pass | Pass | Pass |
| Calculator arithmetic and unique Notepad save/readback | Pass | Pass | Pass |
| Own Win32 install/run/uninstall and registry-only MSI install/uninstall fixtures | Pass | Pass | Pass |
| DHCP, DNS, TCP/UDP, isolated HTTP and normal shutdown | Pass | Pass | Pass |

System Properties/About layouts and login header are visually reviewed at the
recorded 640x480/default-font layout; simulated 96/120/144-DPI font measurements
pass. Actual high-DPI desktops, other languages, classic-menu rendering, broad
third-party installer/application coverage and original signature/catalog trust
are not established. Modified UI hashes invalidate any original signed-file
identity; no trust or WFP bypass is introduced. The test fixtures do not establish
general compatibility. The existing `XP25-Desktop` remains unmodified.

## Milestone 3 original SCM and SMSS, 2026-10-23

The [component reconstruction record](native-components-milestone.md) establishes
these results on separate disposable children of the Milestone 2 images.
Only SCM was first replaced. SMSS was subsequently replaced alone on each frozen,
verified SCM guest. Regsvc, Msgina and UserEnv were then only compiled candidates;
the later extension results above supersede that status.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Native SCM: source-kernel identity / Explorer-Luna | Pass | Pass | Pass |
| Native SCM: standard / pointer / session / networking probes | Pass | Pass | Pass |
| Native SCM: service creation, dependency startup, stop rejection, stop/restart, deletion | Pass | Pass | Pass |
| Native SCM: live mapped checksum / retained binary / original recovery copy | Pass | Pass | Pass |
| Native SCM: logoff/login and Notepad save | Pass | Pass | Pass |
| Native SCM: service shutdown notification / normal guest shutdown | Pass | Pass | Pass |
| Subsequent native SMSS: full regression and service suite | Pass | Pass | Pass |
| Subsequent native SMSS: logoff/login, Notepad, service and guest shutdown | Pass | Pass | Pass |

An installed-SP3-SCM control guest passes the same fourteen service observations
and shutdown fixture. All SCM direct and delay imports resolve by export presence
against the extracted guest modules; both SCM executables have no exports.
This does not establish complete SP3 behavior/security equivalence, remote RPC,
domain-account services, all recovery policies, driver-service transitions or
sustained-load stability. UserEnv was not promoted. The later exact export audit
corrects the ordinal-only interpretation: 207–209 are existing named bodies at
shifted ordinals; missing implementations are CheckXForestLogon and private
200/201. The subsequent adapter still fails boot integration.
Games, accelerated graphics, TLS, IPv6 and additional hardware remain unverified.

## Interactive libvirt desktop, 2026-10-23

`XP25-Desktop` is a persistent `qemu:///system` domain with a loopback VNC
console. Its independent disposable disk was verified sector-identical to
`network-native-kvm-mp-02`, SHA-256
`96ae34bf4c66cb79a1211c6c29e4cf2e48dde99697ed00efe8ce4588657b1940`,
before boot. No reference backing disks are attached. The retained two-vCPU KVM,
qemu32, 512 MiB, i440fx 8.2, IDE, standard VGA and RTL8139 configuration reaches
Explorer/Luna. Six standard, eleven pointer, six session and seventeen network
observations pass; DHCP/DNS and a temporary isolated HTTP fixture were exercised.
A guest-requested shutdown is recorded. This VM is left shut off for interactive
startup; its registration does not broaden the existing hardware, application,
graphics or Internet support claims.
[Exact settings, image hashes and evidence](virt-manager-xp25-desktop.md)

## Milestone 2 networking, 2026-10-23

The [native networking record](native-networking-milestone.md) establishes these
results on fresh source-kernel clones, separately from the historical SP3
installation tests below. Evidence is under `.work/boot-debug-20261022/`.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Source-kernel boot / Explorer-Luna session | Pass | Pass, source MP kernel/HAL | Pass |
| File / registry / pointer regressions | Pass | Pass | Pass |
| Notepad save/reopen | Pass | Pass | Pass |
| IPv4 address/port parsing and invalid-octet rejection | Pass | Pass | Pass |
| TCP and UDP loopback payloads | Pass | Pass | Pass |
| QEMU RTL8139 / original installed NDIS driver | Pass | Pass | Pass |
| DHCP lease `10.25.0.10/24` from `10.25.0.1` | Pass | Pass | Pass |
| Controlled DNS `xp25.test` | Pass | Pass | Pass |
| Isolated TCP/HTTP server | Pass | Pass | Pass |
| Normal guest shutdown / disk check | Pass | Pass | Pass |

KVM also passes explicit interactive authentication (LsaLogonUser zero status /
substatus, matching Explorer/user logon ID), a cold-boot child, and an independent
native-helper build followed by ten network runs, a guest warm reboot and full
probe suite. These are short regression checks. TLS, Internet access, IPv6,
VirtIO, VMware, EC2 and sustained-load/security testing remain unverified.

Only source-built `wshtcpip.dll` was added to the established guest component
set. The original installed Microsoft AFD/TCPIP/NDIS, DHCP/DNS and SCM remain.
The SP3 helper's `RtlIpv4StringToAddressExW` and `RtlIpv4AddressToStringExW`
imports remain incompatible with native ntdll; eight extended IPv4/IPv6 A/W
exports remain absent. The tested original helper uses existing native APIs.
Native Ws2_32 lacks GetAddrInfoW, FreeAddrInfoW and GetNameInfoW; applications
requiring those Unicode resolver APIs remain unverified.
The preserved Milestone 2 image hashes and all per-run commands/results are
linked in the networking record.

The [supplied XP SP3 guest](xp-sp3-guest.md) has booted in KVM. Its stopped
backing-disk SHA-256 is
`e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c`.
Results below apply to that guest and its recorded build overlay, with QEMU
8.2.2, i440fx, qemu32, one CPU, 512 MiB RAM, IDE and standard VGA. They do not
establish a custom source build or other hardware configurations.

## Supplied SP3 runtime regression coverage

| Requirement | Implemented observation | Current execution status |
| --- | --- | --- |
| Kernel boot | QEMU screenshots and guest identity | Supplied XP SP3 boots; source-kernel results are recorded separately below |
| User login | Manual logoff, account chooser, XP25 logon and post-logon probe | Observed once; automated transition test not implemented |
| Explorer | Check shell PID resolves to `explorer.exe` | Pass under Administrator and XP25, including overlay reboot |
| Registry | Volatile HKCU DWORD roundtrip with cleanup | Pass in recorded guest runs |
| Filesystem | Temporary file write/read/cleanup | Pass in recorded guest runs |
| Networking | Bounded IPv4 UDP loopback roundtrip | Pass; no NIC/DNS/TLS test |
| Legacy Win32 applications/games | Application fixtures not supplied | Not tested |
| Driver initialization | Enumerate active kernel driver services | Corrected probe passes: 70 running services, two pages; individual device functionality untested |
| Shutdown | Manual ACPI request and QMP shutdown event | Observed from working desktop; earlier Cirrus first-boot attempt timed out |
| Security regressions | Runtime dependency gate for probe | No guest mitigation/security validation |

`tests/guest/xp_probe.c` reports six implemented observations separately from four
explicitly untested areas. Its exit 0 must not be interpreted as passing this
entire table. [Guest instructions](../tests/guest/README.md)
The original probe failed with `ERROR_MORE_DATA` (234). The corrected probe and
retained failure are documented in [the guest record](xp-sp3-guest.md).

Four checked x86 source kernels have also linked and passed PE inspection.
The first source-kernel selection stopped at incompatible SP3 NTFS imports.
A matching original NTFS driver then reached a checked/free HAL mismatch
(0x79). A checked original HAL also built; its KVM boot reaches the HAL APIC
priority readback assertion (0x8e, STATUS_BREAKPOINT; written 0x3d, read 0x30),
before login. These failed experiments are separate from the verified SP3
runtime. The original UP/MP/PAE target filenames all use MP-enabled checked
configuration here (`NT_UP=0`); multicore runtime had not yet been tested at that
initial checkpoint. The later two-vCPU result is recorded below.
[Native build and boot evidence](native-kernel-build.md)

## Source boot investigation, 2026-10-22

Latest result, 2026-10-23: native LSASRV/Secur32 resolves authentication, and the
tested kernel-held pointer-cookie extension resolves the missing DecodePointer
shell dependency. XP25 authentication, Explorer/Luna, filesystem/registry tests,
Notepad save/reopen and guest-requested shutdown pass under KVM. Fresh TCG and
two-vCPU KVM guests also pass pointer and interactive-session regressions.
[Exact environment, hashes and limitations](source-desktop-milestone.md)
The following paragraphs retain earlier failure evidence.

The reference `xp25-sp3` VM has the libvirt disk/RAM snapshot
`xp25-before-apic-debug-20261022`. All following experiments use disposable
overlays under `.work/boot-debug-20261022/`.

| Configuration | Recorded result |
| --- | --- |
| Original checked kernel/HAL, KVM, qemu32, one CPU | HAL `KfLowerIrql` reads TPR `0x30` after writing `0x3d`; assertion, no login |
| Same, VAPIC disabled | Same readback failure |
| Same, split IRQ chip | Same early failure |
| Userspace APIC with KVM | Host rejects configuration: `KVM does not support userspace APIC` |
| Original checked kernel/HAL, TCG, qemu32, one CPU | `SESSION5_INITIALIZATION_FAILED` (0x71); SP3 ntdll calls SP1 inline syscall bytes as pointer `0x340fd48b` |
| Rebuilt kernel with ntdll pointer ABI, corrected HAL, matching source NTFS/MountMgr, TCG | Syscall pointer is `0x7c90e520`; advances to Session Manager error `0xc0000263` (missing driver entry point); no login |
| Same corrected set, KVM | Passes original readback assertions; stops at checked fast-mutex APC_LEVEL equality check because its TPR comparison also includes the discarded nibble |

The completed HAL revision compares TPR priority classes while retaining
serialization, IRQL validation and mutex ownership checks. All seven recorded
`matrix2-*` configurations pass the earlier APIC stops and reach the SP3 GUI
dependency failure. A negative test supplying the wrong priority class still
raises bugcheck `0x9`. No source-kernel desktop is claimed.

SP3 Win32k imports `MmCommitSessionMappedView` and `SeTokenIsWriteRestricted`,
which the supplied source kernel lacks. SP3 FltMgr also imports the unexported
`RtlAddAccessAllowedAceEx`. These remain incompatible until a matching native
component or a complete, tested implementation is available. Security APIs have
not been stubbed out.

Matching source Win32k subsequently compiled and loaded; USER/GDI initialization
runs and CSRSS appears. CSRSS later exits with `STATUS_INVALID_INFO_CLASS`
(`0xc0000003`). Matching native CSRSS/CSRSRV and BaseSrv builds then succeeded.
With native WinSrv, User32 and GDI32 installed in a fresh clone, the loader
returns `STATUS_DLL_INIT_FAILED` (`0xc0000142`) while loading WinSrv. The direct
imports checked for this component set resolve. An entry-routine trace shows
SP3 Kernel32 returning FALSE on process attachment before User32 starts.
Native Kernel32 builds successfully. Source GUI syscall stubs also need the
shared-page ABI correction: the original stubs execute pointer bytes at
`0x7ffe0300`, causing an access violation at `0x7ffe0309`. Rebuilt User32/GDI32
use the original INT 2E dispatcher directly. A fresh guest records successful
Kernel32 and User32 process attachment. Relinking WinSrv removes its remaining
old stubs and advances to Winlogon, which exits with status `0x80` before login.
SP3 Framebuf imports the missing Win32k `EngBugCheckEx`; matching native Framebuf
loads and removes that error, but hardware pointer initialization fails. VGA
fallback remains unverified. The actual Winlogon loader exception is
`0xc0000139`: SP3 ntdll requests the absent `Kernel32!BaseQueryModuleData`.
Matching native ntdll built and passes this stage in a new clone, then fails on
SP3 Winsock's `RtlIpv6StringToAddressExW` dependency. The revised import checker
includes bound import rows; the earlier scans omitted those symbols.
Authentication and Explorer under the custom kernel remain unverified.
[Detailed boot investigation](boot-investigation.md)

Matching native Winsock and its helper subsequently compiled. Matching IMM32
then removes another embedded SP3 GUI syscall mismatch. Fresh KVM and TCG clones
reach the graphical XP login screen. The loaded kernel is
`\\WINDOWS\\system32\\XP25KRNL.EXE`, checksum `0x33f857`, matching the compiled
input. Authentication fails: LSASS sets unsupported token information class 16
and `LsaLogonUser` returns `0xc0000003`. Matching original LSA is being built.

| Source-kernel milestone gate | Recorded status |
| --- | --- |
| Source kernel loads | XP25KRNL.EXE path and compiled checksum `0x33bcdb` verified live under KVM/TCG; matching MP kernel also verified |
| Graphical login screen | Observed in fresh KVM and TCG clones |
| Authentication | Native LsaLogonUser status/substatus 0; logon ID matches XP25 and Explorer tokens |
| Explorer and Luna desktop | Observed under KVM, TCG and two-vCPU KVM; session probe passes |
| Filesystem and basic applications after login | KVM temporary-file and HKCU round trips pass; Notepad save/reopen verified offline |
| Normal source-guest shutdown from desktop | Guest `shutdown.exe -s -t 0` reaches QMP shutdown state |
| Ubuntu reproduction | Fresh clones launched from Ubuntu; native build-media pipeline executes independently |
| Pointer compatibility/security contract | Eleven checks pass, including 262,144 concurrent round trips and rejected remote/invalid queries; not a general security audit |
| Networking | Historical SP3-helper failure 10022; resolved by the original source-built helper in Milestone 2 above |

Clean rebuilding also exposes absent executive files `exinit.c` and `systime.c`.
Native kernel links use the four supplied i386 prebuilt objects, whose hashes
are recorded in `build-04/prebuilt-inputs.json`; a full rebuild from C/ASM and a
free-build variant are not established.

## Software targets

No specific modern application release has been selected or installed. A target
family does not imply all releases or architectures are feasible.

| Target | Installation | Launch | Functionality | Stability |
| --- | --- | --- | --- | --- |
| Supplied Explorer/Luna | Installed from supplied SP3 ISO | Desktop and shell observed | Basic 640×480 desktop and CD browsing observed | Several sessions; no sustained stability test |
| Control Panel | Present in installed guest | Not tested | Not tested | Not tested |
| Supplied Notepad | Installed from SP3 ISO | Observed | Edit/save/reopen roundtrip; extracted text matches | One short check |
| XP-era DirectDraw/Direct3D games | Not tested | Not tested | Not tested | Not tested |
| Legacy Win32 installers/applications | Not tested | Not tested | Not tested | Not tested |
| Python 3 | Not tested | Not tested | Not tested | Not tested |
| Git | Not tested | Not tested | Not tested | Not tested |
| Current TLS client | Not tested | Not tested | Not tested | Not tested |
| Chromium-based browser | Not tested | Not tested | Not tested | Not tested |
| Newer C/C++ runtime | Not tested | Not tested | Not tested | Not tested |
| .NET application/runtime | Not tested | Not tested | Not tested | Not tested |
| Contemporary developer utility | Not tested | Not tested | Not tested | Not tested |
| One-Core-derived API-set aliases | Not installed | Not tested | 28/arch statically checked | Not tested |

## Hardware and deployment targets

| Target | Verified evidence | Guest support status |
| --- | --- | --- |
| QEMU i440fx 8.2, BIOS, IDE, standard VGA, KVM via libvirt | Supplied XP guest registered in VMM; console screenshot at 640×480; no network interface | Basic desktop observed; accelerated graphics unverified |
| QEMU Cirrus | Text/GUI Setup works; first-boot resolution transition repeatedly blacks out | Desktop transition failed; checkpoint retained |
| Multicore/SMP/modern CPU instructions | Existing source paths only | No new support claim |
| UEFI/GPT/NVMe/AHCI/USB 3.x | No guest experiments | Unverified |
| Modern ACPI/interrupt controllers | Existing ACPI/HAL code only | Unverified |
| Modern GPU/multiple displays/passthrough | Host VFIO node exists | No device or driver validated |
| QEMU RTL8139 Ethernet | Source-kernel KVM UP/MP and TCG: DHCP, DNS, TCP/UDP, isolated HTTP | Verified only in the recorded configurations; see Milestone 2 |
| Other Ethernet/Wi-Fi/IPv6/Bluetooth | No corresponding device/runtime tests | Unverified |
| EC2 | XP omitted from supported import list; i386 imports discontinued | Blocked, no deployment |

EC2 constraints were checked against [AWS import requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html).
Do not mark a target supported based on a source symbol, an API stub, a successful
link, a firmware screen or a device node alone.
