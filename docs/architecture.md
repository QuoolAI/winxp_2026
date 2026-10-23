# Windows XP 25 Anniversary Edition: architecture and source baseline

The product objective is to preserve the Microsoft Windows NT architecture,
kernel, Win32 subsystem, registry, services, Explorer and Luna while backporting
features incrementally. Linux, Wine and ReactOS are not guest foundations. The
existing `Source/XPSP1/NT` layout is retained because the build scripts depend on
it. No changes have been made to that reference tree.

## Identified baseline and completeness

Both `public/sdk/inc/ntverp.h` and `published/sdk/inc/ntverp.h` declare major 5,
minor 1, build 2600 and QFE 1106. Together with the supplied `XPSP1` tree name,
this identifies an XP SP1-era 5.1.2600.1106 baseline, not SP3 or a released
NT 5.2 XP Professional x64 tree. Headers do not authenticate the source's origin,
establish a particular SKU configuration, or prove every component is coherent.

The complete reference inventory contains 277,863 files and 6,322,952,743 bytes.
Every file was SHA-256 hashed. The deterministic manifest hash is:

```text
9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151
```

There are 498 `i386`, 102 `amd64` and 210 `ia64` directories. AMD64 source exists
in the kernel scheduler, memory manager, runtime, HAL and other components, with
x86-hosted AMD64 cross-compilers. This is more than empty scaffolding, but no
AMD64 kernel or OS has been built. Several boot `DIRS` entries select x86/IA64,
and EFI entries select IA64. These do not establish contemporary x86/AMD64 UEFI
support. IA64 and AMD64 are distinct architectures.

The primary build target is original NT 5.1 x86. An AMD64 native kernel attempt
is retained as experimental diagnostics. The future x64 product requires an
identified, legitimately supplied NT 5.2 baseline and independent build/boot
validation. Converting NT 5.1 x86 into x64 is not the implementation strategy.

## Component map

Paths below are relative to `Source/XPSP1/NT`. Presence means source or build
metadata was found; it does not imply that a complete component builds.

| Component | Source area | Notes |
| --- | --- | --- |
| Kernel, executive, scheduler, memory, I/O, security | `base/ntos/{ke,ex,mm,io,se,ps,ob}` | Original Microsoft components |
| Registry/configuration manager | `base/ntos/config` | Preserve hive format and behavior |
| HAL and ACPI | `base/hals`, including `halacpi`, `x86new` | Native architecture-specific implementations |
| Loader, boot video, debugger transports | `base/boot` | Includes loader and BIOS-era boot paths |
| Native user API | `base/ntdll` | Original NT user/kernel interface |
| Session manager and CSR | `base/subsys/{sm,csr}` | Required for native session bring-up |
| Win32 services and client/server layer | `base/win32` | Includes kernel32 sources and export declarations |
| GDI and USER | `windows/core/{ntgdi,ntuser}` | Original graphics/windowing architecture |
| Explorer, shell, Luna | `shell/explorer`, `shell`, `shell/themes` | Preserve native desktop and identity |
| Security/logon | `ds/security`, `ds/security/gina` | `gina/winlogon` is absent |
| Service controller | `base/screg/sc/server` | Original SCM compiled and runtime verified; see native component milestone |
| Filesystems and storage | `base/fs`, `base/busdrv`, `drivers` | New controller support requires specific driver work |
| Network stack | `net`, including `net/tcpip` | Original networking baseline |
| Setup and hive generation | `base/ntsetup`, `mergedcomponents/setupinfs` | Complete bootable payload not established |
| Build environment | `tools`, `public`, `published` | Includes compilers and prebuilt libraries |

The literal unconditional `DIRS` audit reports 342 missing directory references,
including `QFE`, `ds/security/licensing`, `ds/security/gina/winlogon` and
`windows/core/ntgdi/fondrv/otfd`. This is not an NMAKE evaluator: optional and
conditional sections and variable expansion are excluded. Some gaps may be
configuration-specific. Missing Winlogon and service-controller server source
remain material obstacles to a complete original-system rebuild.

The inventory found a preexisting `ntldr`, but no kernel, HAL, Winlogon or cmd
binary under the scanned exact names. The sole source disk-image candidate is
an EFI SDK utility image, not a validated XP OS image. A subsequently supplied
SP3 ISO has now been installed in a [private KVM guest](xp-sp3-guest.md), separate
from the source inventory. Proprietary component completeness and
redistribution authorization have not been established; artifacts stay local.

## Reconstructed build path

`tools/razzle.cmd` derives `_NTDRIVE`/`_NTROOT`, selects host and target tools,
then calls `tools/ntenv.cmd` and `tools/ntuser.cmd`. The offline option disables
internal network/depot dependencies. `ntenv.cmd` supplies `NTMAKEENV`, build
defaults and NMAKE settings; `tools/makefile.def` drives component `sources`
and `dirs` files.

The wrapper invokes the original `tools/x86/build.exe -Z` after Razzle
initialization. `kernel` scope selects `base/ntos`; `base` scope also reaches
HAL, boot and other base components. Kernel linking is described by
`base/ntos/init/up/sources.cmn`: it combines executive libraries with HAL imports,
bootvid, kdcom, sdbapint, lsakrnlp and libcntpr. Presence of these declarations
and libraries did not establish a successful link at the original checkpoint.
The supplied SP3 guest has since linked and statically inspected four checked
x86 kernel variants, plus boot-video/debugger dependencies. Matching original
NTFS and checked ACPI APIC HAL targets have also built. [Native execution record](native-kernel-build.md)

Available tools include x86 `build`, NMAKE, CL, LINK, LIB, ML, RC, MC, MIDL,
BINPLACE, compiler backends, PDB support and Perl, plus x86-hosted AMD64 CL,
LINK and ML64. Embedded CL version metadata reads 13.00.9176 for the x86 driver
and 13.00.9269.1 for the AMD64 driver. The x86 compiler has since executed in the
SP3 guest, reported 13.00.9176, and compiled a 465-byte smoke-test object. The
AMD64 version remains a resource inspection only. CL imports MSVCR70, USER32 and KERNEL32; MSVCR70 is
present alongside the tools, but Windows host services are still required.

The current host is Ubuntu 24.04 x86-64 with Python 3, native GCC, QEMU 8.2.2,
SeaBIOS and privately extracted MinGW tools. The Linux host has no `cmd.exe`, Wine
or PowerShell; the separate supplied XP SP3 guest now provides a native Windows
command/compiler environment. PowerShell is not a prerequisite for
the legacy Razzle path. The wrapper conservatively requires a 32-bit Windows
host: the original Razzle script warns that full-tree 16-bit tools cannot run
on Win64. A clean CMD environment and short paths are required by the original
unquoted batch scripts. See the guest record for actual native build results;
compiler execution alone does not establish a kernel link.

`build/stage.py` creates a disposable copy and compares complete hashed manifests.
`build/attempt.py` protects the reference and records launch failures.
`build/milestone.py` retains source inventory, x86 kernel/base attempts,
experimental AMD64 kernel attempt and both QEMU firmware observations. See
[PROGRESS.md](PROGRESS.md) for actual statuses and evidence locations.

## Runtime and compatibility boundaries

One-Core-API's host `spec2def` and selected forwarding specifications have been
reused in an isolated build. There are 28 statically checked DLLs per architecture,
but no Windows runtime validation. The original XP core is not replaced with
upstream ReactOS Winlogon, services or kernel implementations. Earlier mentions
of these as candidates are source-analysis observations, not an integration plan
under the preservation requirements. [Analysis and evidence](onecore-analysis.md)

No scheduler, memory-manager, mitigation, storage, graphics or network-stack
patch is ready for deployment before a native boot baseline. Keep original
timing, DirectX/DirectDraw behavior, installers, input, audio and graphics paths
available for XP games; validate changes against recorded game workloads.

The BIOS/i440fx/IDE/Cirrus profiles remain diagnostic starting points. A separate
KVM/qemu32/i440fx/IDE/standard-VGA configuration now boots the supplied XP SP3
guest and passes recorded runtime checks. Cirrus failed its first desktop
resolution transition. Source-kernel experiments recorded incompatible SP3
NTFS imports, then a checked/free HAL mismatch, then a checked HAL APIC
priority readback assertion under KVM. Matching original NTFS and HAL builds
resolve the first two dependencies; completed source-kernel login remains
unverified. No GPU-passthrough experiment was run.
Host device nodes do not establish an XP display driver, GPU reset behavior,
IOMMU isolation or legacy-game compatibility. Do not unbind a host GPU as part
of baseline automation.

AWS VM Import currently omits XP from its supported Windows list and states
that i386 imports stopped on April 1, 2026. Its EC2 driver guidance lists
Windows Server versions, not a validated XP ENA/NVMe driver path. Native EC2
deployment is therefore blocked, not supported by these QEMU profiles. No cloud
resources have been created and no image was uploaded.
[AWS import requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html),
[EC2 Windows driver guidance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-windows-instances.html)
