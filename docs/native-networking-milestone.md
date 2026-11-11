# Milestone 2 — native networking restoration, 2026-10-23

The source-built NT 5.1 x86 kernel now runs IPv4 TCP and UDP loopback, an
emulated RTL8139 adapter, DHCP, controlled DNS and HTTP. The change to the guest
component set is the **original source-built `wshtcpip.dll`**. The installed
Microsoft AFD, TCPIP, NDIS, DHCP, DNS, Winsock provider and SCM remain in use.
No kernel or ntdll patch was needed for these networking gates. This milestone
does not establish a completely source-built networking stack or OS.

Private evidence paths below are relative to `.work/boot-debug-20261022/`.
The [desktop baseline](source-desktop-milestone.md), its successful checkpoints,
`Source/` and the installed SP3 reference are preserved.

## Failure and compatibility requirement

The earlier guest probe returned Winsock error 10022. Installed SP3
`wshtcpip.dll` imports two absent native ntdll exports:
`RtlIpv4StringToAddressExW` **and** `RtlIpv4AddressToStringExW`. Its static import
table retains both names even though it was bound to SP3 addresses.
`network-installed-inputs/import-comparison.json` records the actual names and
hashes. The inspected SP3 `mswsock.dll`, `dnsapi.dll`, `dhcpcsvc.dll` and
`iphlpapi.dll` have no missing direct named imports from the native ntdll, Kernel32,
Ws2_32 and Ws2help used here. This is a bounded comparison of these DLLs, not
proof that every SP3 module or dynamically requested function is compatible.

The native ntdll exports the eight non-extended IPv4/IPv6 A/W conversion APIs.
SP3 additionally exports eight `ExA`/`ExW` forms: address-to-string and
string-to-address for both IPv4 and IPv6. All eight remain absent; see
`network-installed-inputs/ntdll-export-comparison.json`. Installing the SP3
helper again would restore its loader incompatibility. General support for
those extended APIs is not claimed.

The native Ws2_32 export comparison also identifies three absent SP3 Unicode
resolver exports: `GetAddrInfoW`, `FreeAddrInfoW` and `GetNameInfoW`. Ws2help's
named exports match. `network-installed-inputs/winsock-export-comparison.json`
records both comparisons. The tested IPv4 resolver path uses `gethostbyname`;
applications requiring these Unicode APIs remain outside this milestone's
verified compatibility. They were not filled with incomplete forwarding stubs.

`Source/XPSP1/NT/net/tcpip/winsock/wshtcpip.c` uses the existing
`RtlIpv4StringToAddressW` and `RtlIpv4AddressToStringW`. Its original
`WSHStringToAddress` parses the port itself. Building this matching helper
removed the demonstrated SP3 import mismatch, so no replacement parser or
success-returning API stub was introduced. The existing IPv4 parser is in
`base/ntos/rtl/str2addt.h`, instantiated by `str2addw.c`/`str2adda.c`.
The original helper has legacy parsing behavior; exhaustive SP3 equivalence,
IPv6, broadcast parsing and malformed-input fuzzing are not established.

The running dependency chain is:

| Component | Contract / observed dependency |
| --- | --- |
| Application → Ws2_32 | Winsock catalog selects the installed Microsoft provider |
| Mswsock → wshtcpip | Transport mapping, socket/address options and IPv4 conversion helper exports; all 16 original helper exports retained |
| Mswsock → AFD → TCPIP | Socket operations reach the Microsoft kernel transport through the original NT interfaces |
| TCPIP → NDIS → RTL8139 | Existing SP3 `RTL8139.SYS` initializes the QEMU PCI NIC; live module list and real traffic recorded |
| TCPIP service | `SYSTEM_START`, `PNP_TDI`, dependency IPSec |
| AFD service | `SYSTEM_START`, `TDI`, no SCM dependency listed |
| DHCP Client | `svchost -k netsvcs`, LocalSystem; depends on Tcpip, Afd and NetBT |
| DNS Client | `svchost -k NetworkService`; depends on Tcpip |
| PlugPlay / RpcSs / SCM | Existing Microsoft service infrastructure retained; running-service and authenticated-session probes pass |

The service relationships come from guest `sc qc`, rather than assumptions
about a newer Windows release. IP configuration, routes and service output are
retained in the readbacks. Basic Winsock operations, DHCP assignment and DNS
answers are also independently visible in packet/server logs.

## Native compilation

`build-22` compiled the original helper with the prepared native Microsoft
13.00.9176 x86 toolchain: three files compiled, one library and one DLL linked,
no build errors. Extracted `wshtcpip.c` exactly matches the reference hash
`923fdc13fdbcc504707d59b3b7fb155fdee06f36dbf81a32c287a1cc6bc3cbe9`.
`build-22-final/inspection.json` records i386, version 5.1.2600.1106, valid PE
checksum and all 16 helper exports. This output is 17,920 bytes, SHA-256
`088396cf54ac0cdffce182788086b43812b22bd9059a6f6ea0dd5224619f7292`.

`build-23` repeated compilation using source-pinned generated transfer media
(`network-build-media-01/manifest.json`). Its independently rebuilt helper has
SHA-256 `1e5329f3ee75a0aafea56e70cc4f18bff7198695c2fa507db47e848b5422dd22`
and was integrated into `network-native-reproduction-01`. `build-24` exercises
the tracked native build-VM launcher from a new clone of build-21. Build logs,
finished markers, commands, media manifests and outputs are retained separately.
Native timestamps can vary; bit-identical PE output is not claimed.

## Runtime evidence

All guests use QEMU 8.2, i440fx 8.2, qemu32, 512 MiB, IDE/BIOS, standard VGA,
the source-built kernel/HAL and the previously verified native user-component
set. The original desktop configuration had **no NIC**. RTL8139 was selected
for this milestone and installed automatically from the existing guest's
Microsoft driver material; nothing was downloaded into the guest.
The extracted RTL8139 driver is i386 version 5.398.613.2003 with a valid PE
checksum; its hash/inspection are retained in `network-driver-readback/`.

| Experiment | Evidence and result |
| --- | --- |
| `network-native-kvm-02` | Fresh baseline clone, first native helper; all 17 network observations pass; six standard, eleven pointer and six session checks pass |
| `network-native-kvm-mp-02` | Fresh clone, independently rebuilt helper, source MP kernel/APIC HAL, two KVM vCPUs; serialized network and regression gates pass |
| `network-native-tcg-01` | Fresh clone, TCG, one vCPU; same network and regression gates pass |
| `network-native-reboot-01` | Child of the normally shut-down first network guest; cold boot retains adapter identity and passes network/standard/pointer/session gates |
| `network-native-reproduction-01` | Fresh baseline clone with independently rebuilt helper; full suite, ten consecutive network runs with zero failures, guest-requested warm reboot, then full suite again |

Every network probe checks startup, IPv4 address/port parsing and invalid octet
rejection, actual TCP and UDP payload round trips, six running services, adapter
address, DHCP server, DNS answer, TCP connect and an HTTP response marker.
The test server is `10.25.0.1:8080`, DNS name `xp25.test`; DHCP assigns
`10.25.0.10/24`. `dnsmasq.log` records DHCPACK and the DNS question/answer,
`http.jsonl` records HTTP 200 requests from the guest, and `network.pcap` retains
the traffic. This includes real NIC, DNS and TCP/IP execution, beyond DLL import
resolution or socket creation alone.

Live debugger inspection matches the loaded `\\WINDOWS\\system32\\XP25KRNL.EXE`
to its compiled checksum (`0x342f9d` for the UP build); the MP inspection uses
the matching MP map. `native-stack-verification.json` records loaded networking
drivers and processes without equating process presence to functional tests.
The first KVM integration also logs off, reaches the account chooser and logs
back in: LsaLogonUser status/substatus are zero, logon ID 146452 matches the
session probe and Explorer token. Screenshots retain Explorer/Luna and Notepad
save/reopen checks. All preserved guests shut down normally and pass image checks.

`network-native-reproduction-01/guest-restart.json` records a guest RESET with
reason `guest-reset`; this is an actual warm reboot, separate from the cold-boot
clone. Ten short repetitions and these reboots are the recorded stability
coverage, not a sustained-load, security, application/game or Internet test.

The first KVM run accidentally staged an old standard-probe binary; it reported
driver enumeration error 234. Its output is retained. Rebuilding tracked
`xp_probe.c` fixes this and produces a six-pass result, including 65 active
driver services over two pages. The test-media generator now rejects stale
probe source/executable hashes. A first namespace launch failed before QEMU
started because a mapped user could not inspect `/proc/1/ns/net`; the launcher
now compares against the namespace identity captured by its parent. Both
failures remain in `network-native-kvm-01` and the earlier probe logs.
The first MP run passed networking/pointers but lacked a session-probe result
after separate UI invocations overlapped probe completion. The evidence checker
rejects that incomplete run; `network-native-kvm-mp-02` repeats the entire
serialized suite in a fresh clone. The obsolete first test CD also queried a
nonexistent driver-service name; the corrected CD queries RTL8139. Neither a
missing record nor a failed diagnostic query is counted as a passing test.

Frozen successful image SHA-256 values (use new children, never boot these
files writable):

| Experiment | SHA-256 |
| --- | --- |
| `network-native-kvm-02` | `bb909fc16caddc43b9a28528aba7e758f7c05a8f08971f2fd04c9a21c0c7874e` |
| `network-native-kvm-mp-02` | `96ae34bf4c66cb79a1211c6c29e4cf2e48dde99697ed00efe8ce4588657b1940` |
| `network-native-tcg-01` | `9184817ced3e4f8267800ca99d7b1ca96495a71e36d63ceac20e694a1da59762` |
| `network-native-reboot-01` | `f915e49ed85ddf228622a718a9d9bc72efc135aeb0a49bbdcd46d4b8b7cb297d` |
| `network-native-reproduction-01` | `2236700a34f1464754b5c54854853c10b9c11f28c9a82c8daea14116e7a8cc36` |

Per-run `network-results.json` checks each latest complete probe group, retains
historical failures and requires independent DHCP/DNS/HTTP/isolation/shutdown
evidence. `file-retention.json` verifies all 19 installed components, including
the helper, against their staged hashes after shutdown. Readbacks retain the
Notepad text. `network-backing-chain-hashes.json` independently confirms the
original SP3 disk remains
`e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c`
and the native-build backing remains
`45301e5c36a678955881721a1f0c9f1014cd2c2a872284bb11951fd3b91c2fd6`.
`network-source-reference-check.json` verifies the 12 earlier patch references
and five original helper files. The 21 existing host regression tests pass in
`network-host-tests-01.log`.

## Isolation and reproducibility from the Linux host

`vm/isolated_network.py` runs under an unprivileged user/network namespace.
Only loopback and a private TAP interface exist. There is no uplink, bridge,
NAT backend or default route; IP forwarding is disabled. Dnsmasq reads no host
configuration, hosts file or upstream resolver and serves the controlled `.test`
zone locally. DHCP advertises no router. The HTTP server binds only the private
address. Namespace/route state, explicit QEMU/dnsmasq commands and packet captures
are recorded. Linux, dnsmasq and Python are host test infrastructure; the guest
continues to execute Microsoft's networking components.

This recipe requires the retained frozen native build VM and Milestone 1 desktop
images. It does not bootstrap the missing OS sources or a new build toolchain.
Choose new names for every run; launchers refuse to overwrite existing outputs.

```bash
python3 build/prepare_native_network.py --output .work/network-build-next
python3 vm/native_build_lab.py --name network-build-next \
  --media .work/network-build-next/native-network.iso
```

After observing the build guest's desktop, run through its Run dialog using the
recorded QMP helper:

```bash
python3 vm/xp_lab.py .work/boot-debug-20261022/network-build-next run \
  'cmd /c D:\build.cmd C:\xpout\network-next'
```

Wait for `NATIVE_NETWORK_BUILD_FINISHED` in that guest's serial log. Request
`shutdown.exe -s -t 0` through the guest; only then use `xp_lab.py ... finish`.
Extract `/nt/net/tcpip/winsock/obj/i386/wshtcpip.dll` and the build log with
`vm/read_guest.py DISK NEW_OUTPUT GUEST_PATH ...`. Its disk must be frozen.
Rebuild the four probes using `build/guest.py --probe xp|network|pointer|session`
with the existing private MinGW toolchain, giving each a new output directory.
Package those directories with `build/prepare_network_tests.py`; static checks
require PE 5.1, XP SDK imports, no C runtime and current source/executable hashes.

```bash
python3 vm/network_lab.py --name network-next \
  --helper .work/network-extracted/nt/net/tcpip/winsock/obj/i386/wshtcpip.dll \
  --probe .work/network-probes/network/network_probe.exe \
  --standard-probe .work/network-probes/xp/xp_probe.exe \
  --pointer-probe .work/network-probes/pointer/pointer_probe.exe \
  --session-probe .work/network-probes/session/session_probe.exe
```

Use `--accel tcg` or `--cpus 2` for the other recorded configurations. The latter
selects the existing matching source MP kernel/HAL. The default backing image is
the frozen build-21 desktop reproduction; `--base` can select a newly frozen
successful network disk for cold-boot regression. QMP UI/screenshot operations
are serialized. CD AutoPlay and initial PnP can change focus: observe the screen
and wait for each operation to complete before entering another command.

Attach the generated test ISO using `xp_lab.py ... hmp 'change ide1-cd0 PATH'`,
wait for the UI to settle, and run `cmd /c D:\regress.cmd`. Wait for its completion
marker and four zero exit records. `D:\stability.cmd` performs ten bounded
network runs. `xp_lab.py ... restart` requests a guest restart and records the
RESET event; run the suite again after the desktop returns. Use
`vm/inspect_native.py` with the matching kernel/map, review its evidence and
resume through QMP. Check Notepad interactively, then shut down normally, finish,
and extract staged components/text to verify retention. `Source/` is never a
build or output directory.
Run `python3 vm/network_results.py EXPERIMENT_DIRECTORY` to validate the
automated evidence after shutdown; interactive authentication/Notepad review
remains a separate requirement.

## Additional virtual hardware

Only RTL8139 on the recorded QEMU/KVM and TCG configurations is runtime verified.
The local QEMU offers E1000, PCnet and VirtIO alternatives; emulation availability
does not establish a usable NT 5.1 driver. [QEMU's device documentation](https://www.qemu.org/docs/master/system/devices/net.html)
describes the separate guest device and host backend.

VMware documents E1000 (82545EM) with XP drivers and legacy Vlance/PCnet32;
VMXNET requires a corresponding VMware driver. These are future controlled
tests, not validated VMware support. [VMware adapter reference](https://knowledge.broadcom.com/external/article?legacyId=1001805)

VirtIO networking needs a native NT 5.1/NDIS-compatible driver and a provenance,
import and runtime audit. The [virtio-win upstream](https://github.com/virtio-win/kvm-guest-drivers-windows)
provides NetKVM sources; its existence is not XP compatibility evidence. No
VirtIO driver was imported, built or installed in this milestone.

AWS separates Xen PV/Intel VF paths from Nitro ENA networking. Its published
Windows driver matrix targets Windows Server releases, with no NT 5.1 x86 entry.
RTL8139 success therefore does not establish EC2 support. No EC2 adapter,
deployment or cloud network was tested. [AWS Windows driver matrix](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-windows-instances.html)

## Milestone 3 prerequisites

The original SCM is `base/screg/sc/server` (`services.exe`), not the absent
`ds/netapi/svcctrl/server`. Native MIDL 6.00.0347 successfully executes its
original `makefil0` with `-Oicf -robust -error all -protocol dce` and creates
`svcctl_s.c`, `svcctl_c.c` and `inc/svcctl.h`. Build-23 retains these outputs;
build-24 also generates Winreg's `regrpc_s.c`, `regrpc_c.c` and `regrpc.h` using
the original Winreg recipe. Logs and hashes are under the respective final
extractions. `build/native-scm-prepare.cmd` reproduces generation in a disposable
build copy. Nothing is copied to the guest's installed SCM/RPC runtime.

SCM's declared link graph includes SDK Rpcutil/Rpcrt4/Rpcndr, Secur32, Netapi32,
ntdll, Userenv, Scesrv and Ntdsapi; private User32p, Crypstub, Trkstub, Wrlib,
Sclib and NCObjAPI; local Umpnpmgr, Winreg server and Svcslib outputs. Supplied
x86 SDK/private libraries exist for the named published inputs. Local targets
still need a build/link audit. PnP has its own `base/pnp/idl` pass-zero RPC
generation; RPC runtime/NDR sources are under `com/rpc/runtime` and
`com/rpc/ndrlib`, with Rpcutil at `com/rpcutil`. Building these is Milestone 3
preparation work, not evidence of a working source-built SCM.

The previously recorded missing executive C files (`exinit.c`, `systime.c`),
absent Winlogon source directory and other inventory gaps remain. The four
hash-pinned executive objects and installed Microsoft Winlogon/SCM are still
required. No broad modernization or SCM replacement was begun.
