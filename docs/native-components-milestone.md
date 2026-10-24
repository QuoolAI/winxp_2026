# Milestone 3 — original system component reconstruction

The original NT 5.1 x86 Service Control Manager now compiles and runs in place of
the installed SP3 SCM in disposable XP25 guests. The acceptance gates pass under
one-vCPU KVM, two-vCPU KVM and one-vCPU TCG. Original SMSS was then integrated
as a separate change on the verified SCM checkpoints and passes the same matrix.
No reference image or user libvirt VM was updated. Work continues from
`1f58fed7c`, retaining the later `XP25-Desktop` registration commit.

This remains a mixed original-source/installed-Microsoft system. It is not a
complete OS rebuild, a complete source inventory of every binary input, or a
claim of general SP3 security and application equivalence.

The later [Regsvc/MSGINA extension checkpoint](native-component-extensions.md)
supersedes the candidate statuses below: both pass individual integration,
Explorer compiles but crashes as a shell, and the exact UserEnv export adapter
passes process-only checks but fails Winlogon boot. The earlier ordinal-only
gap statement about UserEnv 207–209 below is corrected by that full ABI audit.

## Native SCM build

The implementation is `Source/XPSP1/NT/base/screg/sc/server`, target `services`.
Fresh native build overlays start from frozen `build-24/disk.qcow2`, which
already contains the original MIDL-generated SCM and Winreg RPC prerequisites.
`build/native-components-build.cmd` compiles original targets in dependency order:

1. Service support `base/screg/sc/lib` (`sclib`) and registry support
   `base/screg/winreg/lib` (`wrlib`), published within the build copy.
2. PnP IDL and `base/pnp/umpnpmgr`, generating its original import library.
3. Winreg server and `base/screg/sc/svcslib` static libraries.
4. `base/screg/sc/server`, including the reused `svcctl_s.c` RPC server.

The first native attempt compiled SCM but failed linking `_ScDisplayWStrArray@4`.
The original checked implementation is in `sc/lib/strarray.cxx`; the supplied
published library did not satisfy that checked-build reference. Rebuilding the
original library fixes the link. No SCM function, security check or API was
stubbed, and no SCM implementation patch was needed. `scm-build-01` retains the
failure. Native `scm-build-02` and an independent build from build-24,
`scm-build-03`, succeed. Native tools report 29 SCM compilation outputs and one
linked executable; both successful per-target result files contain seven zeros.

Only the compiled `services.exe` is installed at this stage. The new PnP DLL is
not installed: its import library links SCM against the existing Microsoft
`umpnpmgr.dll`. The SDK/private inputs Rpcutil/Rpcndr, RpcRt4, Secur32, Netapi32,
ntdll, User32p, Userenv, Scesrv, Ntdsapi, Crypstub, Trkstub and NCObjAPI remain
provided original libraries. The generated manifest hashes them explicitly;
not all their code has been rebuilt from source in this milestone.

| SCM input/output | SHA-256 |
| --- | --- |
| Installed SP3 `services.exe`, version 5.1.2600.5922 | `c2488c0b7d3c05ca5b23154aedd07efc592b7e5008100fa4416be8dfee551b24` |
| Native build-02, version 5.1.2600.1106 | `a367c4bc875b89bc359324a22d339c62784d0c23bde49e0c14f4c61fabda7d75` |
| Independent native build-03 | `077cf31e82ba1dab6fa9c50d43b6da3faa0ad64ddf5e55b03bcbad67449c8015` |

Native timestamps/checksums vary; bit-identical PE output is not claimed. Both
native outputs have independently verified PE checksums. The live mapped SCM
checksum is 197333 for build-02 and 197816 for build-03; the SP3 control checksum
is 113958. The service probe reads the running process image with the original
XP Toolhelp/ReadProcessMemory APIs. Process presence alone is not the service
behavior gate.

`build/inspect_component.py` handles normal, bound and delay imports, ordinal
exports and PE checksums. Native SCM has 268 direct imports across ten DLLs and
seven delay imports across Netapi32/Ntdsapi. All are present in extracted guest
export tables; both SCM programs have no exports. Native-only direct imports
include TLS functions and the checked DbgPrint/DbgPrintEx/RtlAssert paths.
Static export presence does not validate forwarded targets, dynamic lookup,
unexercised RPC methods or all SP1/SP3 behavioral differences.

## Runtime evidence

Experiments and checkpoints are under `.work/boot-debug-20261022/`. Each uses
QEMU 8.2.2, i440fx 8.2, qemu32, 512 MiB, IDE/BIOS, standard VGA and RTL8139,
with the previously verified source kernel/HAL and native user-component set.
The network is private: local DHCP/DNS/HTTP, no uplink or default route.

| Experiment | Component changed / result |
| --- | --- |
| `scm-sp3-control-01` | Installed SCM control; existing probes, fourteen service cases and shutdown fixture pass |
| `scm-native-kvm-01` | Native SCM build-02, one-vCPU KVM; all gates pass |
| `scm-native-kvm-mp-01` | Native SCM build-02, two-vCPU KVM; all gates pass |
| `scm-native-tcg-01` | Independent SCM build-03, one-vCPU TCG; all gates pass |
| `smss-native-kvm-02` | Only SMSS added to the frozen KVM SCM checkpoint; all gates pass |
| `smss-native-kvm-mp-02` | Only SMSS added to the frozen MP SCM checkpoint; all gates pass |
| `smss-native-tcg-02` | Only SMSS added to the frozen TCG SCM checkpoint; all gates pass |

The existing six standard, eleven pointer, six session and seventeen networking
observations pass. The new service fixture creates two disposable own-process
services, verifies the declared dependency, starts the dependent service and
observes automatic prerequisite startup, requires error 1051 when stopping a
prerequisite with a running dependent, stops both, restarts/stops the first,
deletes both and verifies removal. These are real SCM RPC/service-dispatch calls.

A separate running fixture accepts `SERVICE_CONTROL_SHUTDOWN`, writes a flushed
proof file and is marked for deletion before shutdown. Offline extraction proves
delivery; QMP independently records normal guest shutdown. The later test CD
clears old proof before arming the fixture, so subsequent overlays cannot count
an inherited proof file as a new result. Shutdown remains separate from a host
QEMU stop. Every successful image passes `qemu-img check` after guest shutdown.

Each native SCM and SMSS configuration has observed logoff, the XP25 chooser,
successful interactive re-entry and post-login probes. Notepad saves unique
per-guest text, verified again by offline extraction. Matching-kernel GDB
inspection independently verifies the loaded XP25 kernel path/checksum. The
compiled component and its original recovery copy are rehashed after shutdown.

`component-results.json` requires the existing network/guest gates, fourteen
service cases, zero exit, live SCM checksum, retained image, recovery copy,
shutdown fixture proof and loaded source-kernel identity. Additional SMSS runs
also require its exact retained binary and freshly cleared shutdown proof.
Screenshots, `serial.log`, QMP journals, packet capture, DHCP/DNS/HTTP logs,
Notepad readbacks and normal-shutdown records remain alongside each experiment.

Earlier failures remain separate: the first SCM link error, two missing optional
diagnostic `.err` extraction paths, an early TCG Run-dialog input timing failure,
and a premature TCG finish request which was correctly rejected. Initial SMSS
launches (`*-01`) failed before guest execution because a relative test-media
path was resolved after changing directory. The launcher now resolves it first
and checks QMP readiness; successful retries use `*-02`. No failure is counted
as a passing guest run.

## Additional components and source completeness

The full read-only audit hashes 277,863 files / 6,322,952,743 bytes and retains
the original manifest SHA-256:
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
It reports 342 unconditional literal DIRS gaps. This is not an NMAKE dependency
evaluation: conditional/optional branches, variable expansion and runtime
necessity are not established by that gap count.

| Component | Original source / current status |
| --- | --- |
| SMSS | `base/subsys/sm/server`; native binary `60b33b7a6ca7f1919e263b776ac77b49537dcc522d1f2c165aa130ca6bb8fa70`; integrated after SCM, matrix passes |
| Remote Registry | `base/screg/winreg/regsvc`; Regconn and DLL compile; static contracts inspected, not installed |
| GINA | `ds/security/gina/msgina`; Ginacomn and DLL compile; all 22 named SP3 exports retained, not installed |
| UserEnv | `ds/security/gina/userenv`; IDL, RSOP and five local libraries compile/link; not installed |
| Explorer | `shell/explorer/winnt`; original sources and GUID libraries compile, missing private `browseui.lib` blocks linking; no shell replacement |
| Other shell code | Original Shell32/theme/UI trees exist; no new runtime compatibility claim |
| Networking/security support | Native PnP DLL/import library, Ginacomn and RSOP/IDL libraries compile; only SCM's link inputs are used in guests |
| Winlogon | Required `ds/security/gina/winlogon` source directory absent; installed Microsoft executable retained |
| Executive initialization/time | `base/ntos/ex/exinit.c`, `systime.c` absent; four hash-pinned supplied UP/MP objects remain required |

UserEnv required one small build-copy-only SDK correction: close the missing
parenthesis in `comdef.h`'s `_COM_SMARTPTR_LEVEL2` conditional. The media manifest
records before/after hashes. Its rebuilt DLL omits SP3 `CheckXForestLogon` and
ordinal exports 207–209. This is a concrete compatibility gap; no substitute or
success-returning security stub was introduced. Direct/delay imports resolve in
the inspected guest, but profile/policy/domain behavior remains untested.

Original HSPLIT searches CR-delimited tags. Normalizing its `.w`/IDL inputs to
CRLF in the build media resolves the observed leaked `begin_internal` tokens
and lets the original published-shell target compile. Creating its expected
private output directories enables the original file-inference/copy rules and
the Shguid/Shguidp/Ieguidp libraries. Candidate build-05 advances Explorer's link
to missing `C:\nt\Shell\lib\obj\i386\browseui.lib`. The broader BrowseUI/private
shell dependency chain remains unfinished; no unverified shell was installed.

The existing One-Core provenance analysis identifies ReactOS/Wine dependencies
in replacement core implementations. These remain excluded. No compatible,
independently implemented Winlogon substitute has been validated or installed.
Installed Microsoft loader/Winlogon/LogonUI, shell, runtime/service DLLs and
drivers remain dependencies. Full original-source accounting is incomplete.

## Reproduce and recover

Generated artifacts stay under `.work/milestone-3-20261023/`; successful build
and guest disks stay under `.work/boot-debug-20261022/`. Always choose new names.
Never boot frozen references writable, edit `Source/`, or use `XP25-Desktop` as
a build/test disk. These commands require the retained prepared native build VM,
legitimately supplied Microsoft tools/media and the Milestone 2 guest images.

```bash
python3 build/prepare_native_components.py --output .work/scm-media-next
python3 vm/native_build_lab.py --name scm-build-next \
  --base .work/boot-debug-20261022/build-24/disk.qcow2 \
  --media .work/scm-media-next/native-components.iso
```

Observe the build guest's desktop before input, then run through QMP:

```bash
python3 vm/xp_lab.py .work/boot-debug-20261022/scm-build-next run \
  'cmd /c D:\build.cmd C:\xpout\scm-next'
```

Require `NATIVE_COMPONENT_BUILD_FINISHED`, zero per-target results and the actual
executable. Request `shutdown.exe -s -t 0`, wait for QMP status `shutdown`, then
use `xp_lab.py ... finish`. Extract with `vm/read_guest.py`; inspect the PE and
compare imports/exports using `build/inspect_component.py`. Build the service
probe with `build/guest.py --probe service` and the existing private MinGW tools;
`prepare_network_tests.py --service PROBE_DIRECTORY` packages it with the four
current probes. Provenance gates reject stale probe source/executable hashes.

`vm/network_lab.py --component /WINDOWS/system32/services.exe BINARY` installs
exactly one new system component in a fresh overlay. Supply the established
helper/probe arguments as in the networking runbook. It records the old binary
as `recovery-services.exe` on both host and guest (`C:\xp25`), hashes the backup,
copies the replacement offline and verifies the readback. Use `--cpus 2` or
`--accel tcg` for the other configurations. Optional `--test-media` and
`--startup-script` attach a read-only test CD and a self-removing XP25 Startup
fixture; no baseline startup configuration is changed. The fixture's source
hash is retained in `inputs.json`.

Run `D:\regress.cmd`, review screenshots/authentication/Notepad, inspect the
loaded kernel, then run `D:\arm-shutdown.cmd` and shut down through Windows.
TCG supports `xp_lab.py ... run COMMAND --settle-seconds 3`. Only after observed
guest shutdown should the disk be frozen and extracted into its `retention/`
directory. `vm/component_results.py --expected-scm BINARY` validates the result;
for SMSS add `--expected-component BINARY --guest-target /WINDOWS/system32/smss.exe`.

Recovery uses a **new child** of a stopped/frozen experimental disk and the same
single-component installer, pointing at its host `recovery-services.exe` (or
`recovery-smss.exe`). This restores the exact original bytes without changing
the failed image or reference. The installed SCM control independently verifies
the preserved SP3 binary's service behavior.

`build/record_component_manifest.py` creates the private machine-readable
`components-manifest.json` from original source recipes, compiled binaries,
the source audit and passing frozen experiment reports. It records dependencies,
compatibility fixes, tested artifact variants, runtime gates, recovery paths,
remaining installed/provided Microsoft inputs and explicit source gaps. Candidate
outputs without passing runtime reports remain `compiled_not_integrated`.
Host regression results and all per-stage logs are retained privately. No source,
binary, inventory or guest image is uploaded, pushed, deployed or sent to CI.

The final host run passes 24 tests, including rejection of reference-tree output,
changed evidence behind an older passing result, and a modified native PE checksum.
`preservation.json` confirms unchanged definitions for all five existing VMs and
the same running `xp25-sp3` process. `reference-hashes-after.json` verifies all
eight recorded frozen reference/build images retain their hashes and read-only
modes. The full source manifest also remains unchanged.

## Preserved verified image hashes

| Frozen experiment disk | SHA-256 |
| --- | --- |
| `scm-native-kvm-01` | `ebca1a8d64cab8d54aa49a4c097d66b8f0ddc0ec07b831a757e6f69945b975c9` |
| `scm-native-kvm-mp-01` | `b4c5bf7adbcd04a9d3582298cb91f19b8e58dd53798deb633dca9bc974f7e7fb` |
| `scm-native-tcg-01` | `9b91901015d42e0515cad3c8d831b6eddb61184e2564e4814e07628ebe2f6674` |
| `smss-native-kvm-02` | `3ae9e2ad6c8352a8b69b11f7cdc344cc606566d597fd7bd17f3f09e27449e883` |
| `smss-native-kvm-mp-02` | `dbad56a92503482c6594e792248adcf556a7f66c478b70ef8c2fe4af27787a69` |
| `smss-native-tcg-02` | `2d4f1b7ad256911d959ebf83ea78dba9909d0c412289e1a84bf8c87312f04d23` |

Use only fresh children of these read-only disks. `XP25-Desktop` remains on its
separate Milestone 2 disposable disk; it was not silently promoted to these new
components. The earlier working reference images remain available for recovery.
