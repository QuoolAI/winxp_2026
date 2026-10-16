# Development progress

## Current checkpoint

Milestone 1's diagnostic acceptance is established through its precise-blocker
alternative. A custom Windows XP build and boot have **not** been achieved.
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
failure. Native batch behavior has not been verified on Windows. Firmware
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

## Next independent implementation: native regression probe

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
games, security mitigations and shutdown remain explicitly untested. No guest
execution has occurred. [Guest instructions](../tests/guest/README.md)

The compiler was extracted privately, without system-wide installation. Its
driver reports `i686-w64-mingw32-gcc-posix (GCC) 13-posix`. Packages and tools are
retained under `.work/toolchains/`. MinGW builds the new probe only; native XP
kernel compilation still requires its original Windows toolchain environment.

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

1. No Windows command host/build guest or supplied XP installation media. Native
   compilation did not start; no source-level compiler fixes are justified yet.
2. Missing original Winlogon and SCM server source directories, licensing and
   font-driver references, plus other literal gaps. Full rebuild completeness is
   unresolved; no substitute OS core was adopted.
3. No linked custom kernel/HAL or complete bootable payload. An empty disk or
   unrelated EFI SDK image would not meet the boot criterion.
4. No identified NT 5.2 XP Professional x64 product baseline. AMD64 code and
   standalone PE32+ aliases are not evidence of a supported x64 XP build.
5. No physical hardware/passthrough or modern-driver tests. Host device nodes
   do not establish guest support.
6. AWS's documented import path omits XP and discontinued i386 imports on
   April 1, 2026. EC2 remains a platform/driver feasibility blocker.
   [AWS requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html)

Next runtime milestone: use a compatible 32-bit Windows build guest with the
verified disposable copy to reach the original compiler, retain kernel/HAL/boot
link diagnostics and resolve reproducible failures. When authorized XP guest
media is available, execute the native probe with image-hashed serial evidence
before adding login/shutdown and legacy-game tests. Kernel modernization and
hardware/security support claims remain gated on that baseline.
