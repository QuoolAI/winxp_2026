# Compatibility matrix

No custom XP image has booted. `Not tested` means no installation, execution or
stability evidence exists; it is not a prediction of compatibility. Guest runtime
and hardware support must cite an image hash, exact version, environment and logs.

The [supplied XP SP3 guest](xp-sp3-guest.md) has booted in KVM. Its stopped
backing-disk SHA-256 is
`e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c`.
Results below apply to that guest and its recorded build overlay, with QEMU
8.2.2, i440fx, qemu32, one CPU, 512 MiB RAM, IDE and standard VGA. They do not
establish a custom source build or other hardware configurations.

## Runtime regression coverage

| Requirement | Implemented observation | Current execution status |
| --- | --- | --- |
| Kernel boot | QEMU screenshots and guest identity | Supplied XP Professional 5.1.2600 SP3 boots; custom XP boot blocked |
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
configuration here (`NT_UP=0`); no multicore runtime was tested. [Native build and boot evidence](native-kernel-build.md)

## Source boot investigation, 2026-10-22

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
(`0xc0000003`). Winlogon, authentication and Explorer under the custom kernel
remain unverified. [Detailed boot investigation](boot-investigation.md)

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
| Ethernet/Wi-Fi/IPv6/Bluetooth | No network-adapter tests | Unverified |
| EC2 | XP omitted from supported import list; i386 imports discontinued | Blocked, no deployment |

EC2 constraints were checked against [AWS import requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html).
Do not mark a target supported based on a source symbol, an API stub, a successful
link, a firmware screen or a device node alone.
