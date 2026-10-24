# Native Regsvc, MSGINA, UserEnv and Explorer checkpoint

This continues `8e575ae1c` and the reconstruction begun at `1f58fed7c`.
Original Regsvc and MSGINA are integrated **individually** and pass one-vCPU KVM,
two-vCPU KVM and one-vCPU TCG. The working original-source kernel, SCM, SMSS,
networking, XP25 branding and installed shell are preserved. Native Explorer
now compiles. Its shell integration and the UserEnv adapter's boot integration
fail and are excluded from the accepted image. Winlogon remains an installed
Microsoft dependency.

Generated artifacts and evidence are private under
`.work/milestone-3-extensions-20261023/` (abbreviated `E` below); individual guest
runs are under `.work/boot-debug-20261022/` (`L`). Nothing is pushed or uploaded.
This checkpoint does not complete independent SP3 UserEnv reconstruction, a
licensed clean installation image, or full OS reconstruction/source accounting.

## Accepted component sequence

The first new stage starts from frozen `L/brand-final-tcg-01/disk.qcow2`, SHA-256
`d4fa9505a725fcc670ddfd443d4179e5871ef32d27d8073e6e7e04f6b4774f85`.
Only `WINDOWS/system32/regsvc.dll` changes. The second stage starts from the
accepted, normally stopped Regsvc KVM image and replaces only `msgina.dll`.
Two-vCPU runs select the previously verified matching original MP kernel/HAL;
no new kernel implementation is introduced. UserEnv and Explorer experiments
also start from accepted frozen parents, never from failed candidates.

| Component | Source path below `Source/XPSP1/NT` | Accepted binary SHA-256 |
| --- | --- | --- |
| Regsvc | `base/screg/winreg/regsvc` | `f8d0960a1c50b04bc8a7b8b5b078eb6b403d2bfac27ec3b4058209079a08fa1b` |
| MSGINA | `ds/security/gina/msgina` | `2f227623789841b4b9a159c7699e75de577565c7cb9397eff5951a04ba0d72ce` |

Both are the previously compiled native `candidates-01` outputs. No Regsvc or
MSGINA implementation patch, security-success stub or substitute core is added.
The existing native compilation pipeline and prerequisite evidence remain in
[the SCM reconstruction record](native-components-milestone.md).

| Experiments | Result |
| --- | --- |
| `regsvc-sp3-control-02` | Installed-SP3 Regsvc control passes |
| `regsvc-native-kvm-01`, `regsvc-native-kvm-mp-01`, `regsvc-native-tcg-01` | Original Regsvc passes all three configurations |
| `gina-sp3-control-01` | Installed-SP3 MSGINA control on original Regsvc passes |
| `gina-native-kvm-01`, `gina-native-kvm-mp-01`, `gina-native-tcg-01` | Original MSGINA passes all three configurations |

All six native experiments pass the established 54 standard/pointer/session/
network/service observations, 21 distinct Regsvc cases, 17 branding observations,
Win32 fixture/Calculator checks and all five MSI fixture steps. Regsvc has
repeated observations: two complete RPC round trips, two stopped-server
rejections and four bounded child-worker exits. MSGINA runs add four host/GINA
checks. They also pass actual logoff/re-entry, a unique Notepad save with offline
readback, live original-kernel identification, fresh service-shutdown notification,
guest-requested shutdown and `qemu-img check`.

`tests/guest/regsvc_probe.c` starts/stops/restarts RemoteRegistry, reads the
Regsvc PE checksum actually mapped in its service host (native **83714**, SP3
**110179**), and uses `RegConnectRegistryW` with `\\.` for real local named-pipe
Winreg RPC. A NULL computer name would merely open the local registry and is
not the transport test. The fixture creates, writes, reads and removes only its
own HKLM key; local and RPC reads agree. Calls while the server is stopped must
fail. The original service-running state is restored. Workers have bounded
timeouts; only a probe's own child can be terminated on timeout.

The first installed-SP3 control (`regsvc-sp3-control-01`) failed before native
integration: reading the service-host module required enabling the probe's
existing debug privilege, and `\\127.0.0.1` SMB transport returned error 53.
Probe-02 corrects module inspection and uses the named-pipe test with explicit
stopped-server negative controls. That failure remains recorded. Remote network
SMB/RPC compatibility is **not** established by these local RPC tests.

`tests/guest/gina_probe.c` locates current-session Winlogon and reads its mapped
MSGINA header (native **1005061**, SP3 **1034987**). The logged-on user is denied
write/create/WRITE_DAC access to the Winlogon desktop in both control and native
runs. Manual tests in each native configuration log off, open classic logon,
reject one deliberately incorrect fixture password, accept the existing empty
password for the local XP25 account, lock with Win+L, and unlock back to
Explorer/Luna. No account password, authentication policy or activation setting
changes. `gui-review.json` hashes the reviewed screenshots and saved text.
This is local-account regression evidence, not domain, FUS, smart-card, RDP or
security-equivalence certification.

Each run retains `component-results.json`, `extension-results.json`, serial/QMP
journals, packet/DHCP/DNS/HTTP evidence, live-kernel inspection, normal-shutdown
record and offline file extraction. `vm/extension_results.py` requires fresh
passing core evidence, complete latest probe groups, actual mapped checksums,
exact retained binaries, unchanged captured compatibility identity and freshly
armed shutdown evidence. Incomplete later groups cannot reuse an earlier pass.

The changed component's original bytes are saved on the host and at
`C:\xp25\recovery-regsvc.dll` or `recovery-msgina.dll`. Recovery copies are checked
after normal shutdown. To recover, stop only the disposable guest and restore
its recorded original to that single target in a new child, then rerun the
suite. Frozen verified parents remain the immediate fallback. Do not edit a
running NTFS disk or a reference image.

## UserEnv: exact export adapter, rejected boot integration

The original DLL compiles, but the earlier ordinal-presence audit was incomplete:
SP3's `#207`–`#209` are existing named implementations at shifted ordinals, not
three absent function bodies. The native DLL has 48 named exports and private
ordinals 100–158. SP3 has 49 named exports, adds `CheckXForestLogon` at 159 and two
unnamed implementations at 200/201. All named ordinals must match the inspected
SP3 table; adding only three tail entries would silently misbind clients.

`build/userenv_sp3_compat.py` creates a deterministic, readonly additional export
section. It pins the exact 49-name/110-ordinal SP3 map, preserves all original
section bytes and function RVAs, the original private 100–158 mappings, imports
and every non-export data directory, and recomputes the PE checksum. Only the
unavailable implementations forward using standard PE forwarders:

| Export | Retained original implementation |
| --- | --- |
| `CheckXForestLogon` / 159 | `ue51sp3.CheckXForestLogon` |
| unnamed 200 | `ue51sp3.#200` |
| unnamed 201 | `ue51sp3.#201` |

`ue51sp3.dll` is an unchanged copy of the existing SP3 UserEnv, SHA-256
`9c5409ecbd2c3b89c80f0a59b96220178e790a7d78967c6281d56eb1965e9ecd`.
The adapted native DLL is
`1c20325340bf8c865257447f7389ebfd969a4ae10d822614ecc1942cbf55fd60`.
This is **not independent implementation of those three security functions**.
Their ABI/semantics are not guessed and no success-returning substitutes exist.
The original SP3 binary remains an explicit proprietary dependency.

Native linker attempts `userenv-compat-build-01/02` retain their failures
(duplicate ordinal warning under /WX, then unresolved forwarder-only library
symbols). No failed native output is used. The final adapter operates on the
already successfully native-built UserEnv; it does not claim those missing
bodies compiled from source. Microsoft describes the PE export-forwarder format
in its [PE specification](https://learn.microsoft.com/en-gb/windows/win32/debug/pe-format).

`userenv-sp3-control-01` passes fourteen baseline ABI/profile cases. Replacing
only UserEnv with the adapter plus its unchanged forwarding dependency in
`userenv-native-kvm-01`, `userenv-native-kvm-mp-01` and `userenv-native-tcg-01`
fails before a usable desktop: Winlogon terminates with `c0000005`, STOP
`c000021a`. The paused-before-boot `userenv-abi-trace-01` captures the first
Winlogon access violation at **0x0100ced1**, a write through NULL. Exception,
trap and stack bytes are retained. This locates the observed failure; it does
not establish its root cause or justify patching Winlogon/security/licensing
code. No such patch is made. Failed disks are frozen with `failure.json` and
are never represented as normally accepted boots.

An independently testable fallback, `userenv-process-only-01`, loads the exact
adapter and helper from a readonly CD in the probe's own user process. All
fifteen cases pass: complete named ordinal agreement, original private export
presence, exact three forward targets, real token/profile A/W paths and buffer
contract, all/default user paths, environment creation/destruction and user
environment expansion. The mapped candidate checksum is **712045**. The OS
UserEnv remains byte-identical to the original, and all other regressions and
normal shutdown pass. `userenv-process-results.json` records this limited result.
It does **not** override the rejected boot tests. Domain/cross-forest, GPO,
policy-security behavior and general UserEnv equivalence remain unverified.

## Original Explorer now compiles

`build/native-shell-build.cmd` runs in the disposable native Windows build VM.
It preprocesses the original BrowseUI and Shdocvw `.src` export specifications
using `shell/makefile.inc`'s public/two-pass-private rules, then uses native LIB
to generate `browseui.lib`, `browseuip.lib`, `shdocvw.lib` and `shdocvwp.lib`.
These are import libraries for the existing original runtime DLLs, not new
stub implementations. Seven NONAME entries need explicit x86 stdcall decoration:

| Import library | Symbols / original ordinals |
| --- | --- |
| BrowseUI | `SHCreateFromDesktop@4` / 106; `SHExplorerParseCmdLine@4` / 107; `UEMRegisterNotify@8` / 118; `GetInfoTip@16` / 135 |
| Shdocvw | `WinList_Init@0` / 110; `WinList_Terminate@0` / 111; `RunInstallUninstallStubs@0` / 125 |

Original headers and failed linker references establish these decorations.
Runtime ordinals are unchanged. Original Shfusion, Stockthk, Stock and
Explorer/Desktop2 (`dv2host`) build before Explorer/Winnt. No source implementation
is changed. `shell-native-build-01` preserves missing Stockthk; build-02 preserves
the seven unresolved decorated references; **build-03 succeeds**, including 24
Explorer compilation units, one executable and binplace. Each successful target
and import-library result is zero. The script also propagates failed target
results to its overall exit status.

The extracted original executable SHA-256 is
`3cc2c4913053e42aca4eec1652712dad2de15aea08d00b14abdb8acac2df10d9`.
`E/explorer-import-check.json` finds no missing direct or delay imports in the
extracted guest modules. Static symbol availability does not establish private
shell ABI/behavior equivalence.

`prepare_branding.py --only-explorer` applies the same two reviewed Start-menu
resource labels while preserving code, VERSIONINFO and other resources.
`explorer-native-kvm-01` installs only this candidate in a fresh accepted-parent
child. It reaches the user session but displays the Explorer crash dialog;
`dwwin.exe` is observed and no functioning shell is accepted. Task Manager
requests a normal guest shutdown without sending an error report. The failure,
console screenshots, loaded source-kernel identity and shutdown are retained.
No full regression pass is claimed; the working installed Explorer remains in
the accepted image. Further SP1/SP3 private-shell diagnosis is required.
An additional `explorer-abi-trace-01` attempt fails in the GDB remote protocol
before a valid exception capture; it is frozen separately and establishes no
additional crash cause or runtime acceptance.

## Image packaging and licensing boundary

`build/package_verified_desktop.py` requires fresh passing component, extension
and GUI reports for the KVM/MP/TCG matrix, exact frozen disk hashes and a wholly
frozen private backing chain. It flattens the accepted MSGINA KVM desktop into
a standalone disk, verifies virtual-sector equality with `qemu-img compare`,
checks the image, rehashes the source chain and freezes the result. It edits no
guest file or boot setting. The result is:

`E/engineering-image-01/XP25-Components-Engineering.qcow2`

Its manifest records the image checksum, hardware profile, original-media
provenance, retained component hashes, matrix evidence, remaining original
binaries and limitations. It includes the working native SCM/SMSS/Regsvc/MSGINA
stack, prior native kernel/networking and branding. Rejected UserEnv and
Explorer candidates are excluded. Use a fresh writable copy for each boot;
the frozen artifact has no dependency on the reference backing disks.

This is a **private preinstalled engineering disk**, not a Windows Setup ISO
or a clean redistribution-ready installation. It includes the existing source/
build payload and recovery files. Reproduction verifies virtual-sector content;
bit-identical QCOW2 metadata or native PE timestamps are not claimed.

The packaged disk has SHA-256
`1263ec2b8816d9093249fd49a25a2a50eded2f7b05ae6c92f5d9b7d35a81d613`,
virtual capacity 32 GiB, and no backing file. `E/components-manifest.json` and
the package's copy record seven component source paths, checksums, direct/delay
dependencies, compatibility fixes, exact accepted variants and rejected runs.
`build/record_component_manifest.py` rechecks acceptance evidence before producing
that manifest; a tested different variant cannot certify an untested binary.

The old installation record identifies a third-party modified XP SP3 ISO and
its hash; that is provenance information, not proof of entitlement. The request
for an identified authorized local media/license record remains unanswered.
No new Microsoft media is downloaded, activation/licensing mechanisms are
unchanged, and no licensed-image or redistribution claim is made. Producing a
clean, appropriately licensed installation image remains pending those inputs
and validation on that installation baseline. The tool explicitly records
`license_entitlement_established: false` and `windows_setup_iso: false`.

See [the independent Winlogon investigation](winlogon-investigation.md) for the
missing implementation, public WLX/GINA contracts, private NT startup obligations
and staged acceptance route. Installed Winlogon, original SP3 UserEnv/Explorer,
runtime/service DLLs, device drivers and four supplied executive objects remain
dependencies; the manifest is not a complete account of all proprietary inputs.

## Reproduction

Use new output/run names; all commands require the retained private prepared
native Windows build VM and the supplied tools/assets. Never use a running user
VM or alter `Source/`. Build Regsvc/MSGINA using the earlier native-candidates
pipeline. For the resolved shell build, make a readonly CD containing
`build/native-shell-build.cmd` as `build.cmd`, launch a fresh native-build child
from `component-candidates-05/disk.qcow2`, and run:

```text
cmd /c D:\build.cmd C:\xpout\shell-next
```

Require individual zero results and the actual EXE, then stop normally and
extract it using `vm/read_guest.py`. Prepare the UserEnv experiment separately:

```bash
python3 build/userenv_sp3_compat.py \
  --native .work/milestone-3-20261023/candidates-03-extracted/nt/ds/security/gina/userenv/main/obj/i386/userenv.dll \
  --reference .work/milestone-3-20261023/userenv-installed-inputs/WINDOWS/system32/userenv.dll \
  --output .work/userenv-adapter-next
```

Build probes with `build/guest.py --probe regsvc|gina|userenv`; UserEnv additionally
requires `--userenv-reference` for its generated exact SP3 ordinal contract.
Use the supplied host toolchain and a new `.work/` output. `E/test-media-02`
contains the Regsvc suite; 03 adds MSGINA, 04 adds UserEnv, and 05 adds its
process-only candidate test. Fixed preboot CDs avoid cached/hot-swap batch issues.
Their per-file manifests and full QMP command journals preserve executed inputs.

`vm/network_lab.py` creates a new private networking child with one explicit
`--component /WINDOWS/system32/NAME.dll BINARY` (or `/WINDOWS/explorer.exe`).
It retains the original and verifies staged readback. `--userenv-package` permits
only the hash-checked companion of that one UserEnv experiment. `--cpus 2` and
`--accel tcg` select the other configurations. `--pause-for-debugger` leaves
firmware paused for first-failure tracing. Every test network has no uplink;
shared libvirt settings are not changed.

After GUI review, full regressions, matching-kernel `vm/inspect_native.py`
inspection (resume afterward), freshly arming the shutdown fixture and actual
guest shutdown, freeze/extract and run `vm/component_results.py` followed by
`vm/extension_results.py`. Do not count host stops, crash shutdowns, process
presence, inherited proof files or export presence as functional acceptance.

Reproduce the private engineering package from the accepted matrix:

```bash
python3 build/package_verified_desktop.py \
  --run .work/boot-debug-20261022/gina-native-kvm-01 \
  --matrix .work/boot-debug-20261022/gina-native-kvm-mp-01 \
  --matrix .work/boot-debug-20261022/gina-native-tcg-01 \
  --provenance .work/xp-sp3-install-20261018/input.json \
  --output .work/xp25-engineering-next
python3 -m unittest discover -s tests -v
```

The host suite passes 33 checks, including deterministic UserEnv ABI adaptation,
original code preservation, corrupt-input rejection, incomplete-probe rejection,
stale evidence rejection and changed frozen-checkpoint rejection. Source/reference
and existing-domain preservation records remain under `E`; all 277,863 source
files retain manifest SHA-256
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
The sequential final inventory was stopped during image-conversion I/O; the
dedicated eight-worker verifier completes the full per-file comparison and
records `source-preservation.json`. All six inactive domain XMLs are unchanged.
The original `xp25-sp3` process remains unchanged. `XP25-Anniversary` is running
at session start and shut off at the final read; its original process ended
during the task without any agent lifecycle operation. No domain registration,
guest-file mutation, start/stop or shared-network change is issued to user VMs.
