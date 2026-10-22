# Development progress

## Current checkpoint

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
Framebuf driver has compiled for the next experiment. No source-kernel login or
desktop has been established, and no assertion was ignored.
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
work stops in CSRSS initialization before login. Earlier failures remain
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
   established. Original NTFS and checked HAL builds resolved the first two
   source-boot dependencies. The live KVM stop is the checked HAL APIC readback
   assertion. Earlier Linux launch failures remain historical.
2. Missing original Winlogon and SCM server source directories, licensing and
   font-driver references, plus other literal gaps. Full rebuild completeness is
   unresolved; no substitute OS core was adopted.
3. Four source kernels are linked, with boot-video/debugger dependencies built.
   The checked ACPI APIC HAL and matching NTFS now build. A complete custom OS
   rebuild remains unverified. The
   recorded source-kernel boot attempt has not established a completed startup.
4. No identified NT 5.2 XP Professional x64 product baseline. AMD64 code and
   standalone PE32+ aliases are not evidence of a supported x64 XP build.
5. No physical hardware/passthrough or modern-driver tests. Host device nodes
   do not establish guest support.
6. AWS's documented import path omits XP and discontinued i386 imports on
   April 1, 2026. EC2 remains a platform/driver feasibility blocker.
   [AWS requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html)

Next native milestone: resolve the recorded source-kernel boot dependencies and
observe startup with loaded-kernel identity, login, probe and shutdown records.
Game fixtures, accelerated graphics, hardware and security validation remain
outstanding. The supplied SP3 guest and linked source kernels have separate
evidence; a full custom OS rebuild is still incomplete.
