# XP build and VM baseline

Checkpoint: 2026-10-15 (America/Los_Angeles; artifacts use UTC on 2026-10-16).

This page retains the original host-only checkpoint. The later
[2026-10-18–19 supplied XP SP3 guest record](xp-sp3-guest.md) establishes a local
Windows runtime, probe results and shutdown evidence. It supersedes this page's
historical statements that no XP media or Windows guest was available.

The source inventory and offline QEMU diagnostic harness work. Native compilation
and Windows boot have not been achieved. No files under `Source/` were changed.

Subsequent work reused a pinned One-Core-API revision to build isolated forwarding
DLLs on Linux. See [the analysis and build results](onecore-analysis.md). That
experiment adds linked compatibility artifacts while the native XP build and
Windows boot remain unverified.

## Verified results

| Check | Result | Evidence |
| --- | --- | --- |
| Source inventory | 277,863 files; 6,322,952,743 bytes; every file hashed | `.work/milestone-1-r3/inventory/` |
| Source version headers | Both identify 5.1.2600, QFE 1106 | `public/sdk/inc/ntverp.h`, `published/sdk/inc/ntverp.h` |
| Manifest identity | Matches the first inventory exactly | SHA-256 below |
| Literal `DIRS` audit | 342 gaps; no case collisions detected | `inventory.json` |
| Native x86 and amd64 attempts | Blocked before compiler launch: no `cmd.exe` on Linux | `.work/milestone-1/build-{x86,amd64}/` |
| x86 and amd64 firmware runs | `harness_passed`; Windows boot `not_attempted` | `.work/milestone-1-r2/qemu-{x86,amd64}/` |
| Regression checks | 5 passed, including a real QEMU snapshot run | `python3 -m unittest discover -s tests -v` |

SHA-256 of the complete, sorted `files.jsonl` manifest:

```text
9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151
```

This is the hash of the manifest containing paths, sizes and per-file SHA-256
values, not a hash of concatenated source bytes. All artifacts under `.work/`
are private and ignored by Git. They are preserved locally rather than committed.

The audit now accepts continuation backslashes followed by whitespace, Windows
path separators, case-insensitive directory names, and empty architecture tags.
It verifies that entries are directories, rejects source directory symlinks, and
handles a missing optional published version header. These corrections reduced
the previous 389 reported gaps to 342. It still skips conditional sections,
optional directories and variable references; it does not evaluate NMAKE or
establish which gaps are reachable in a particular build.

## Known source limitations

The following literal manifest references are absent:

| Manifest | Absent entry |
| --- | --- |
| `dirs` | `QFE` |
| `ds/security/dirs` | `licensing` |
| `ds/security/gina/dirs` | `winlogon` |
| `windows/core/ntgdi/fondrv/dirs` | `otfd` |

`ds/netapi/svcctrl/client` is present; `ds/netapi/svcctrl/server` is absent.
The earlier `base/win32/services` component probe used the wrong path. The
inventory now distinguishes the service-control client from the server.

Kernel, HAL, loader and compiler directories are present, but presence alone
does not prove that a kernel can link. The named-binary scan found an existing
`ntldr`, but no `ntoskrnl.exe`, `hal.dll`, `winlogon.exe` or `cmd.exe` by those
names. Its sole disk-image candidate is an EFI SDK image, not an established XP
installation. No XP installation ISO or installed Windows disk has been supplied.

The headers identify NT 5.1. AMD64 directories and cross-compilation tools do not
establish an NT 5.2 / XP x64 product baseline. The amd64 VM profile tests the
harness only; Windows compatibility remains unverified for both profiles.

## Repeat the checks on Linux

Use a fresh output directory for every run; the scripts refuse to overwrite an
existing one. Python 3, QEMU 8.2's i440fx machine type and SeaBIOS are available
on the current host. No Python packages are required.

```bash
python3 -m unittest discover -s tests -v

python3 build/inventory.py --hash-all --output .work/next/inventory

python3 vm/run.py --arch x86 --firmware-smoke \
  --bios /usr/share/seabios/bios-256k.bin --output .work/next/qemu-x86

python3 vm/run.py --arch amd64 --firmware-smoke \
  --bios /usr/share/seabios/bios-256k.bin --output .work/next/qemu-amd64
```

The disk regression test skips if `qemu-system-i386` is absent. The other four
checks do not need QEMU. The real VM test verifies the temporary qcow2 overlay
through QMP, checks the input disk hash after execution, and checks that no PCI
network adapter is attached. A blank disk is deliberately reported as
`guest_unverified`, never a successful Windows boot.

## Observe supplied Windows media

For an existing installation disk, use an explicit format:

```bash
python3 vm/run.py --arch x86 --disk /path/to/xp.qcow2 --disk-format qcow2 \
  --bios /usr/share/seabios/bios-256k.bin --seconds 60 \
  --output .work/next/xp-disk
```

For installation media, replace the disk arguments with `--iso /path/to/xp.iso`.
The harness uses TCG, one CPU, IDE storage, Cirrus VGA and no network adapter.
Disk writes go to a temporary snapshot and are discarded; the ISO is read-only.
Input media and explicit BIOS files are hashed before and after the run. Logs,
QMP observations and `screen.ppm` are saved in the output directory.

Runs are bounded to 1–300 seconds and do not provide interactive installation or
persistent guest preparation. Firmware success exits 0. Media observations exit
2 with `guest_unverified`, even if the screen appears to show Windows; inspect
the screenshot and logs to determine progress. Failures also exit 2, so read
`result.json` to distinguish them. QMP's `running` status only says that the VM
is executing.

## Next native build step

A compatible 32-bit Windows build host is required by the current native
wrapper. It rejects 64-bit Windows and WOW64 because parts of the full source
tree use 16-bit tools. Use a disposable source copy at a short path without
spaces, a clean command prompt, and a fresh output directory. Do not run legacy
build scripts against the reference checkout.

On the Windows host, the batch wrapper can be invoked without Python:

```bat
C:\xpbaseline\build\native-build.cmd C:\ntcopy x86 checked kernel C:\xpout\kernel-01
```

Here `C:\ntcopy` must contain `tools\razzle.cmd` and the rest of the NT source
copy. For a machine with compatible Python 3, the launcher also records a JSON
result and captures failures before the batch script starts:

```bat
python C:\xpbaseline\build\attempt.py --source C:\ntcopy --arch x86 --flavor checked --scope kernel --output C:\xpout\kernel-02
```

The wrapper initializes the supplied Razzle environment in offline mode, targets
`base\ntos` for kernel scope, and records native build logs. It has now been
exercised in the [supplied guest](native-kernel-build.md): its path quoting and
child-failure detection were corrected, and four x86 kernels linked. A zero command
exit code is not evidence of a linked kernel or bootable OS: inspect build errors,
output PE files and their dependencies before progressing to boot experiments.

The prepared 32-bit guest now supplies the native command/compiler environment.
A complete OS rebuild still needs a concrete plan for the
absent components; the current harness does not reconstruct them or supply
replacement binaries.
