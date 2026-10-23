# Source-kernel desktop milestone — 2026-10-23

The original NT 5.1 x86 kernel reaches an authenticated XP25 Explorer/Luna
desktop under QEMU/KVM. The recorded guest passes file/registry checks, saves
and reopens a Notepad document, and shuts down normally. This is a source-kernel
milestone on an installed Microsoft XP SP3 system, not a complete source-built
XP distribution. Winlogon, Explorer and other installed Microsoft components
remain in use. Source/ and the working xp25-sp3 reference guest are unchanged.

All evidence paths below are relative to `.work/boot-debug-20261022/`.

## Verified configuration and evidence

QEMU 8.2.2, pc-i440fx-8.2, KVM, qemu32, one vCPU, 512 MiB RAM, BIOS/IDE,
standard VGA, ACPI APIC HAL and no network adapter. `matrix27.py` creates a
fresh disposable child of the frozen `matched-hal-preboot.qcow2` image, stages
the recorded inputs and starts QEMU with debugger/serial/QMP capture.

| Gate | Evidence in `pointer-compat-kvm/` |
| --- | --- |
| Source kernel loads | `native-stack-verification.json`: loaded path `\WINDOWS\system32\XP25KRNL.EXE`, base `0x80a02000`, checksum `0x33bcdb` matches compiled input; guest serial independently prints the same path |
| Graphical login | `after-auth-break.png` shows the XP25 account chooser; `relogin-progress.png` shows personal-settings loading |
| Authentication | `authentication-success.jsonl`: interactive LsaLogonUser, status/substatus zero; the second captured logon has ID 131677 |
| Authenticated user/shell | Serial session probe identifies XP25; its authentication ID 131677 matches the debugger result and Explorer's token; visible window station and Default desktop pass |
| Explorer and Luna | `authenticated-desktop.png`, Task Manager and Notepad screenshots; Explorer has a functioning taskbar and Run dialog |
| Filesystem and registry | Standard probe passes temporary-file write/read/cleanup and volatile HKCU DWORD roundtrip |
| Basic applications | Task Manager opens; Notepad edits, saves, closes and reopens `C:\xp25\desktop-roundtrip.txt`; offline `notepad-readback.txt` matches the 49-byte text |
| Shutdown | Guest `shutdown.exe -s -t 0`; `normal-shutdown.json` records QMP shutdown before QMP quit |
| File retention | `file-retention.json`: all 18 staged inputs still match after normal shutdown; `image-check.log` passes |

Frozen successful disk SHA-256:
`655b3a363040e99160ab9ac595e2c2e232355dce8fe332ec8b4663384d6b3ca0`.
Internal snapshot `source-desktop-verified` preserves the authenticated desktop
before shutdown. Copy this frozen image before any snapshot restore or boot;
do not write to the preserved evidence image or its read-only backing chain.

| First successful component | SHA-256 |
| --- | --- |
| Checked source kernel, build-20 | `87312667e59fd9494013f9f415ed19aeea4e7e9aae01e3b25e6798af44b2e0d2` |
| Native ntdll with pointer APIs | `d7fbc119c9059686ca611f655e7419a3d7316cf23689837224fcc66c1da8e391` |
| Native Kernel32 with forwards | `a5426114689ec25a1a9062f600a19f524a302a52d93f7e523f59744dcda2c14a` |

`inputs.json` records every other component and its preceding installed hash.
`pointer-native-inspection.json` records native PE versions/checksums;
`source-reference-check-pointer.json` verifies all 12 affected reference files
against their original hashes. No proprietary file is committed or uploaded.

## Corrections and regressions

The original APIC stop was a checked HAL comparison of a complete TPR byte
after KVM retained its priority class. The small correction keeps the APIC
serialization read and validates the priority class. It does not remove IRQL
or mutex-ownership checks. The earlier seven-configuration matrix passes this
stage. Repeating wrong-class injection with the new kernel still produces
bugcheck 9 (`pointer-regression-wrong-irql/result.json`).

Later failures were version mismatches between the SP1-era sources and SP3
installed components. Matching original NTFS, MountMgr, Win32k, CSR, BaseSrv,
Kernel32, User32/GDI32/WinSrv, ntdll, Winsock/helper, IMM32 and LSA resolve the
recorded boot/login dependencies. GUI stubs use the original INT 2E dispatcher
with unchanged service numbers and argument cleanup. Matching LSA resolves
TokenAuditPolicy without a success stub or disabled auditing check.

The final shell failure was absent DecodePointer. The new pointer patch adds
a tail field without changing existing EPROCESS offsets, retains a compile-time
layout/size check, uses a lazily and atomically initialized kernel-held cookie,
and permits only the current-process pseudo handle for class 36. Native ntdll
queries that state per operation; Kernel32 forwards the two APIs. Failures
raise status rather than silently return an unencoded pointer. The observed
installed SP3 x86 XOR/counter-mixing behavior is documented in
`sp3-pointer-inspection.json`. It is pointer obfuscation, not a cryptographic
random-number facility or a general security-hardening claim.

The same 11 pointer checks first passed against the installed SP3 APIs, then
against the native implementation under KVM, TCG and two-vCPU KVM: boundary
values, 262,144 concurrent round trips, stable encoding, distinct processes,
and rejection of real/other-process handles and invalid lengths/buffers.
Six session observations also pass in all three source-kernel configurations.
Live path/checksum inspection uses each target's matching kernel map.
Regression runs are `pointer-compat-tcg/` and `pointer-compat-kvm-mp/`.
These short tests do not establish game compatibility, device support or
long-term stability.

The standard source-guest probe has five passing implemented observations and
one failure: UDP loopback returns 10022. SP3 wshtcpip requests the absent native
ntdll export RtlIpv4StringToAddressExW. Login, games, security and shutdown are
explicitly outside that probe's coverage; the separate records above establish
login/shutdown. Networking is not claimed to work.

## Reproduce from Ubuntu

The supplied native toolchain and prepared `C:\nt` copy remain in the frozen
build-host chain. This recipe requires that prepared copy and its generated
prerequisites, described in [the native build record](native-kernel-build.md).
It does not bootstrap a complete Windows build environment from absent sources.

Prepare new private transfer media from the immutable reference:

```bash
python3 build/prepare_native_boot.py --output .work/rebuild-boot-media
```

The generator applies both tracked patch recipes, copies only the four
hash-pinned supplied executive objects and writes a private ISO/manifest.
Attach that ISO to a disposable native build-host overlay and run:

```bat
D:\build.cmd C:\xpout\fresh-boot-build
```

The batch rejects an existing output directory. It performs a clean kernel
compile, preserves its missing-object failure, restores only the four supplied
objects, requires the final link to pass, and rebuilds three HALs, ntdll and
Kernel32. Nonempty build error logs or native NMAKE failures fail the stage.
Build-21 executed this exact tracked recipe; `pipeline-media-01/manifest.json`,
`build-21/serial.log`, `build-21-final/xpout/boot-pipeline-01/` and
`pipeline-native-inspection.json` preserve inputs, commands, logs and outputs.
Native timestamps can change hashes; bit-identical PE output is not claimed.
The independent `pipeline-reproduction-kvm/` guest loads the rebuilt kernel
with matching checksum `0x342f9d`, reaches Explorer/Luna, passes all pointer and
session observations and completes guest-requested shutdown.

`matrix31.py` boots the independently rebuilt inputs. To repeat its fresh-clone
workflow, select a new test name; the existing result directory is preserved:

```bash
python3 - <<'PY'
import sys
from pathlib import Path
root = Path('.work/boot-debug-20261022').resolve()
sys.path.insert(0, str(root))
namespace = {}
exec((root / 'matrix31.py').read_text().split('m.main(wait=True)')[0], namespace)
m = namespace['m']
name = 'source-desktop-repeat-01'
assert not (root / name).exists(), 'choose a fresh test directory'
m.JOBS = [dict(m.JOBS[0], name=name)]
m.main(wait=True)
PY
```

The orchestrator uses an exclusive lock and refuses an unreconciled QEMU PID.
Its automatic result intentionally requires interactive verification. Use the
recorded QMP helper for screenshots/keys; wait for each UI command to finish
before attaching a debugger or entering the next command. CD AutoPlay can
change focus. Run the standard probe, the separately built session/pointer
probes and Notepad, then request shutdown through the guest and verify QMP
shutdown before quitting QEMU. See the per-run journals for executed commands.

The extra probes build reproducibly with no additional guest runtime:

```bash
python3 build/guest.py --probe pointer --toolchain .work/toolchains/mingw-binutils/usr/bin --output .work/pointer-probe-new
python3 build/guest.py --probe session --toolchain .work/toolchains/mingw-binutils/usr/bin --output .work/session-probe-new
```

## Next integration stages and exact source gaps

The corrected source inventory is `corrected-source-inventory/inventory.json`.
An earlier SCM absence finding used `ds/netapi/svcctrl/server`. The original
`services.exe` target actually exists at `base/screg/sc/server/sources`, with
its C++ implementation, sibling client/library sources and SVCCTL RPC inputs.
Generated `svcctl_s.c` and native dependencies still need preparation and an
actual build; source presence does not prove buildability. Winlogon's declared
`ds/security/gina/winlogon` directory is absent.

| Stage | Work and acceptance gate |
| --- | --- |
| Preserve baseline | Keep successful disk/RAM checkpoint and immutable SP3 reference; every integration gets a new child disk |
| Original networking helper | Build `net/tcpip/winsock` (wshtcpip), inspect imports, test UDP loopback in a fresh clone; keep NIC/Internet support unverified |
| Additional original components | Prepare SCM's RPC/private-library graph and build it; consider matching SMSS, GINA/UserEnv, shell/theme components individually; require login/service/app/shutdown regressions at each step |
| Missing executive C | Obtain matching legitimate exinit.c and systime.c before claiming a full kernel rebuild from C/ASM or a clean free-build pipeline |
| Missing Winlogon | Obtain the matching original implementation before claiming a complete source-built native OS; retain the installed Microsoft Winlogon meanwhile |
| Application compatibility | Add actual XP-era application/game fixtures, graphics and service tests; preserve NT 5.1 x86 calling conventions, registry/service contracts, Explorer/Luna and original Microsoft core |

The pinned [One-Core analysis](onecore-analysis.md) identifies ReactOS/Wine/NDK
and generated-RPC dependencies in its Winlogon/services implementations.
Those replacements are excluded by this project's preservation rules. SCM's
newly located original source also removes the premise for replacing it.
Open-source QEMU/GDB and host build tooling remain usable without becoming
guest OS dependencies. No alternative has been validated as a drop-in original
Winlogon replacement, and none was installed. General modernization has not begun.

Automatic usage-limit resumption retains its earlier exact blocker: the open
Codex TUI owns the session writer, so `codex exec resume` was rejected. The
supervisor stopped on that non-rate error; it does not override session ownership
or promise unattended continuation. Per-build and per-boot checkpoints remain
available for the existing session.
