# Supplied XP SP3 guest baseline

Session: 2026-10-18–19 America/Los_Angeles (2026-10-19 UTC). All media, disks,
screenshots, command records and guest logs are private under
`.work/xp-sp3-install-20261018/`.

## Installation input

The user authorized installation from a user-supplied Windows XP Professional
SP3 installation ISO kept outside the repository. Size: 647,823,360 bytes. SHA-256:

```text
3855a4049663edb2c7b7b11b448a86e01274a4d1a9bb49392420bdb61f830a0e
```

The volume is `GRTMPVOL_EN`. It contains `WIN51IP.SP3`, nLite unattended
settings, an embedded product key, and DriverPacks setup hooks. This is the
specific supplied, customized SP3 installation medium; it does not establish
the provenance or integrity of a pristine Microsoft distribution. No Microsoft
components were downloaded. Product keys are not recorded in tracked files.

The source reference remains NT 5.1.2600.1106 (SP1-era). An installed SP3
guest is a runtime and potential build host, not a rebuild of that reference.

## VM configuration

| Setting | Value |
| --- | --- |
| Emulator | QEMU 8.2 (distribution package) |
| Acceleration | KVM; API 12; QMP reports enabled |
| Machine | `pc-i440fx-8.2` |
| CPU | `qemu32`, one virtual CPU |
| Memory | 512 MiB |
| Firmware | QEMU's default SeaBIOS |
| Storage | New 32 GiB qcow2 disk, IDE; ISO attached read-only |
| Display | Cirrus during installation; standard VGA for the working desktop |
| Serial | COM1 captured to a host file |
| Network | No virtual NIC (`-nic none`) |

The existing server VM and its assigned devices were left running. This guest
uses no physical disks, passthrough devices, network shares, or replacement OS
components. The installer selected the newly created virtual disk and NTFS
quick format.

## Evidence and commands

`input.json` records the input identity and KVM preflight. `commands.jsonl`
records QEMU/media commands, QMP requests and responses with timestamps.
`qemu-command.json` records the latest launch command. Numbered PNG/PPM files
record installation and desktop observations. `control.py` is the retained
session helper; it invokes QEMU/QMP directly and does not infer OS health from
process presence.

The initial guest probe was the previously built executable, SHA-256:

```text
9442f469f533395ae911a7201450d95a86bbaf683d08dffb6a767ffafb859a9e
```

The probe's six checks cover OS identity, Explorer presence, a volatile registry
roundtrip, temporary-file I/O, bounded UDP loopback, and active driver-service
enumeration. Login transitions, games, security mitigations and shutdown are
separate observations, never implied by a successful probe exit.

Native source transfer media is generated from the existing verified
`.work/milestone-1-native-stage/NT` copy. UDF preserves names exceeding Joliet's
filename limit. The guest copy belongs at `C:\nt`; a manifest check compares
277,863 expected paths and sizes (6,322,952,743 bytes). That check is not a
per-file guest SHA-256 verification.

The transfer and native kernel build have since completed. See the
[native build record](native-kernel-build.md) for batch preparation, generated
prerequisites, four linked kernels, hashes and boot-test evidence.

## Installed guest and runtime results

The supplied medium completed installation and booted Explorer with Luna at
640×480 using standard VGA. Its unattended settings selected the product key
and initial Administrator session; Setup did not request the user-supplied key.
The local `XP25` account was subsequently created, added to Administrators, and
logged in (its credentials are kept outside the repository). Computer name:
`XP25-BASELINE`.

WMI and file-version observations from the guest:

| Item | Observed value |
| --- | --- |
| OS | Microsoft Windows XP Professional, 5.1.2600, Service Pack 3 |
| Guest RAM | 536,264,704 bytes reported by WMI |
| `ntoskrnl.exe` | 5.1.2600.6419 |
| `hal.dll` | 5.1.2600.5574 |
| `explorer.exe` | 6.0.2900.5634 |
| `kernel32.dll` | 5.1.2600.6293 |

The first probe passed five observations and failed driver enumeration with
234 (`ERROR_MORE_DATA`). The old probe assumed one allocation following a
size query would hold the complete list. It now consumes bounded 4 KiB pages
using the resume handle, rejects non-progress, and limits enumeration to 256
pages. No extra imports or guest runtime dependencies were introduced.

The corrected executable SHA-256 is:

```text
40f06be4905044ff91ed4acd858e91aac8ee82f0f5a7bd680bdfcca7fabc47f9
```

All six checks then passed under Administrator and under `XP25`, with exit 0.
Driver enumeration observed 70 running driver services across two pages.
The old failure and corrected results are retained together in
`serial-xp-sp3-20261019-082323.log`. Compilation/import inspection is in
`probe-paged/`; five focused host checks passed in `host-tests.log`.

Manual logoff reached the account chooser (`51-logoff.png`); selecting `XP25`
reached a new desktop (`52-xp25-login.png`) and a passing probe
(`53-xp25-probe.png`). These are manual transition observations. The probe
itself still reports login transitions, games, security and shutdown as
`not_tested`.

An ACPI shutdown from the working desktop produced QMP `SHUTDOWN` with
`guest=true`, `reason=guest-shutdown`. Offline `qemu-img check` then passed.
The stopped disk was hashed and made read-only before creating a build overlay.

| Artifact | SHA-256 |
| --- | --- |
| Installed `xp-sp3.qcow2` | `e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c` |
| Empty `native-build.qcow2` before its first boot | `137fcfe121ffe1fb76dfd39df4166ba44a3829ff870c00ba867253ba1246bd4b` |
| UDF `native-source.iso` | `65138409477244aa5d37edda8fc1bfc2d0c745deeb22f0a7704d70bbefff6db5` |

The installed backing image is 1,954,217,984 bytes (32 GiB virtual capacity).
`baseline-checkpoint.json` records the configuration, hash, probe identity,
shutdown observation and overlay creation. The overlay depends on the backing
file at its recorded absolute path; retain both files together.

## Original compiler smoke test

While copying the disposable source, the guest executed the original compiler
from the read-only UDF image:

```bat
echo int answer(void) { return 42; } > C:\xp25\smoke.c
D:\tools\x86\cl.exe /c /FoC:\xpout\smoke.obj C:\xp25\smoke.c > C:\xpout\cl-smoke.log 2>&1
```

It reported Microsoft 32-bit C/C++ 13.00.9176 for 80x86 and produced a 465-byte
`smoke.obj`. `58-compiler-result.png` and
`serial-native-build-20261019-083158.log` retain the observation. This establishes
native compiler/object generation only, not kernel compilation, linking or boot.

## Display and installation limitations

With Cirrus, the first-boot resolution prompt repeatedly led to a black screen
and returned to the prompt. An attached VNC client did not change that result.
The internal snapshot `cirrus-oobe-blocked` preserves the blocked state. An
ACPI shutdown request there did not complete within 45 seconds; QEMU was then
stopped explicitly. That stop is **not** a successful Windows shutdown.

Changing to standard VGA allowed the same installation to reach the desktop.
XP still displays a hardware-driver wizard on boot; it was cancelled. Basic
640×480 desktop rendering is observed, but an accelerated display driver,
higher resolutions, DirectDraw/Direct3D and games are unverified. No driver was
downloaded or substituted. The media's SATA driver packs were not exercised by
the IDE configuration. No NIC, external networking, sound or passthrough was
tested.

## Use the XP guest in Virtual Machine Manager

The persistent system libvirt domain `xp25-sp3` is registered and currently
running from `dev-session.qcow2`. It uses the same one-CPU `qemu32`, 512 MiB,
i440fx 8.2, IDE, standard VGA and no-network profile. VMM's VNC display is
bound to loopback; the VMM console can show and control it. It is not configured
to autostart.

Start it from VMM or the shell:

```bash
virsh start xp25-sp3
virt-manager --connect qemu:///system
```

VMM lists `xp25-sp3` under the system connection. `virsh domdisplay xp25-sp3`
reports the current loopback VNC display. The domain boots to the XP desktop;
the Found New Hardware Wizard may appear and can be dismissed.
Log on as `XP25` (credentials are kept outside the repository). The source-kernel boot entry remains
experimental: KVM stops at the checked HAL APIC assertion, and TCG retries did
not establish a loaded-kernel identity or login. See the native build record.

Stop Windows through VMM or request a guest shutdown:

```bash
virsh shutdown xp25-sp3
virsh domstate xp25-sp3 --reason
```

Wait for `shut off` before starting it again through VMM. This disk is the same
writable development child used by the direct QEMU helper. Never start the
libvirt domain and `control.py start dev-session.qcow2` at the same time; both
would try to write that one qcow2 overlay. If using the helper instead, first
stop the libvirt domain. The helper's `quit` action is a host stop, not a
Windows shutdown.

The domain is persistent, but its autostart setting is off. The registration
XML, UUID, access permissions and console verification are recorded in
`.work/xp-sp3-install-20261018/libvirt-registration.json` and
`xp25-sp3.libvirt.xml`. The read-only `native-build.qcow2` and `xp-sp3.qcow2`
backing files must stay at their recorded paths with the writable overlay.
