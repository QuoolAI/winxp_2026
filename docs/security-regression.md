# XP25 security regression framework and record (Milestone 8)

Evidence is under `.work/security-20261111/` (`W`) of the `xp25-security`
worktree; build-VM runs are under `.work/boot-debug-20261022/` (`B`). Every run
boots a disposable overlay of a hash-verified image in a network namespace
without an uplink, and is frozen read-only afterwards. Failed runs are kept
with a `failure.json`.

Passing these tests shows that the specific operations they attempt are
refused and that the listed functions still work. It does **not** show that the
system is free of vulnerabilities; see the [threat model](security-threat-model.md).

## Framework

| Piece | Role |
| --- | --- |
| `tests/security_core.c`, `tests/test_security.py` | Host tests: policy tables (no rule may name a critical service), backup codec (malformed and out-of-table records rejected), path/port/event rules, fixture invariants, scanner, kernel-export patch, cross-build import contract. 12 tests |
| `tests/guest/security_probe.c` | In-guest negative tests as an ordinary account, as a restricted token, and administrator controls ([description](../tests/guest/README.md)) |
| `XP25Sec.exe verify`, `XP25Audit.exe report` | The tools' own verification and findings, including a deliberate-change (drift) test |
| `vm/security_network.py` | Namespace-side scanner: 60 repeated NetBIOS name-service probes, 1,113 TCP ports, 8 UDP services and ICMP echo against the guest from the adjacent network, inside a window in which the guest keeps broadcasting NetBIOS name queries |
| `vm/security_fixtures.py` | Guest suites per role: `regression`, `audit`, `harden`, `image-install`, `proof`, `rollback` |
| `vm/security_lab.py` | Overlay, offline staging with hashes, QEMU in the namespace, logon to the XP25 Winlogon from its serial events, guest-requested shutdown check |
| `vm/security_results.py`, `vm/security_matrix.py` | Gates from serial records, result files read from the frozen disk, QMP event and scans; nothing is decided from screenshots |
| Established suites | The AI suite (55 + 7 cases, `ai_probe.exe` `94a1b060…`) and the compatibility CD (`native-tests.iso` `c3b851d3…`: standard, pointer, session, network, service, Remote Registry, GINA, UserEnv, branding, MSI install/removal, shell and profile probes), unchanged |

Coverage of the required checks:

| Requirement | How it is tested |
| --- | --- |
| Ordinary users cannot modify protected system files | Ordinary-account probe: create in `system32`, `WINDOWS`, `drivers`; open `ntdll.dll`, `winlogon.exe`, the kernel, HAL, NTFS driver, UserEnv companion, SAM hive, `hosts`, XP25 broker and tools for writing |
| …or protected registry locations | 19 `HKLM` keys: Run, Winlogon, Image File Execution Options, AppInit, LSA, Services, firewall policy, Terminal Server, Session Manager, policies, Internet zone, script classes, XP25 policy and baseline |
| Restricted processes cannot acquire privileges | Restricted-token probe in a Job Object: debug, load-driver, take-ownership, restore and TCB privileges; opening LSASS, Winlogon, services, CSRSS and the broker for injection; `WRITE_DAC` on owned objects; breaking away from the job |
| Secure Winlogon desktop stays protected | Open the `Winlogon` desktop for read, write, hook and `WRITE_DAC` from all three contexts, including the administrator |
| Disabled network services are not listening | Namespace scan; `XP25Audit` listener table; baseline service states |
| Unnecessary services stay disabled after reboot | `XP25Sec verify` and the probe after the restart, and again after the whole workload |
| Settings cannot be silently reverted by ordinary users | Unprivileged `XP25Sec rollback`/`apply` and `XP25Audit snapshot` must exit 5; service reconfiguration, firewall stop and store writes denied; the SYSTEM broker must refuse to stop the firewall |
| Audit events are recorded | The probe finds the account-management and failed-logon records it caused in the Security log; the audit reports them |
| Administrative recovery remains possible | An administrator re-enables Remote Registry, the unchanged Remote Registry probe passes, the baseline is applied again; `rollback` role |
| Compatibility | The established suites, plus the XP25 Winlogon logon, `licdll` admission and Explorer identity records on every boot, and a guest-requested power-off |

## Builds

| Build | Command and run | Result |
| --- | --- | --- |
| Kernel export | `build/prepare_kernel_exports.py --output W/kernel-exports-media-01` (ISO `7e508a11…`), `vm/native_build_lab.py --name sec-kexport-01 --base W/reference/build-vm/disk.qcow2` (`cc5156ee…`), `D:\build.cmd C:\xpout\sec-kexport-01` | `XP25_KEXPORT_BUILD_EXIT=0`. `ntoskrnl.src` in the build VM matched the reference before the change. UP kernel `b9531947…809d9`, MP kernel `42662074…ad01`; exports 1,464 → 1,465, added `KeFlushQueuedDpcs` only; sizes unchanged |
| Security tools, native | `build/prepare_security.py --output W/native-media-04` (ISO `1beed42d…`), build VM run `sec-native-04`, `build/security_collect_native.py … --output W/native-06` | `/W4 /WX` clean, 17 sources match the media. `XP25Sec.exe` `77229eac…d672` (51,200 bytes), `XP25Audit.exe` `c8080c85…bca5` (66,048 bytes); every import present in the guest's DLLs. Earlier builds kept: `sec-native-01` and `-02` failed on four `/W4` findings (uninitialized-variable paths, `AF_INET`); `sec-native-03` (`621ade6e…`, `43895024…`) predates the broadcast-response rule |
| Security tools and probe, MinGW | `build/security_build.py --toolchain … --guest-modules W/guest-modules-01/WINDOWS/system32 --output W/mingw-13` | Static checks passed; `security_probe.exe` `d36935e3…a035` |
| XP25 AI build 11 | `build/prepare_ai.py --output W/ai-native-media-11` (ISO `f01aed1e…`), build VM run `sec-ai-native-11` on `W/reference/build-vm-ai/disk.qcow2` (`c2194f6d…`), `build/ai_collect_native.py … --output W/ai-native-11` | `XP25_AI_BUILD_EXIT=0`, 91 sources match. `xp25agent.dll` `0517e28d…416e`, `XP25Broker.exe` `ff16fd87…3836`, `ClippyAI.exe` `c25358cd…d3a7`, `RoverAI.exe` `5dd86d61…7f07`, `RoverAIBand.dll` `0e28ddc3…3a51`. Only change from build 10: the service policy in `xp25_policy.c` |

Host tests: `XP25_MINGW=<main worktree>/.work/toolchains/mingw-binutils/usr/bin
python3 -m unittest discover -s tests -p test_security.py` → 12 tests OK;
`python3 -m unittest discover -s tests -p test_ai.py -k PortableCoreTests` → OK
with the new policy checks.

## Before hardening

Base for all three runs: AI image-05 (`ec22f45b…be2a`) plus `winlogon.exe`
build 10 (`e3a9cdca…df93`) written offline; single-vCPU KVM.

| Run | What | Result |
| --- | --- | --- |
| `pre-up-02` | Established suites on the combination, nothing installed | AI 55/0 and 7/0; all 16 compatibility exits 0; no failed case; XP25 Winlogon logon, `licdll` admission; `shutdown.exe -s` printed "The network path was not found" and did nothing; shut down from the Start menu (`SHUTDOWN guest=true guest-shutdown`). Disk `cbde128b…` |
| `audit-up-01` | Audit, probe and scan on the original kernel | Scan: TCP 135 and 139 open, 1,111 closed, none filtered; UDP 123 and 137 answered; ICMP echo answered. `netsh firewall show state`: "The service has not been started". Ordinary account: 65 denied, **1 allowed** (`ue51sp3.dll`). Restricted token: 56 denied, **12 allowed**. `XP25Sec verify`: 69 deviations. Audit: 23 high, 135 medium findings. Disk `fa2bbb56…` |
| `audit-kx-up-01` | The same with the relinked kernel | Firewall running. Scan: nothing open, 1,113 filtered, no UDP answer, no ICMP reply. Probe unchanged (the kernel fix does not touch access control). Disk `2f350b07…` |
| `audit-kx-up-02` | Relinked kernel, AI build 10, probe with the broker case | An **ordinary account stopped the firewall through `XP25Broker`**; the following scan again found TCP 135 and 139 open and UDP 123/137 answering. Disk `74a21124…` |
| `audit-kx-up-04` | Relinked kernel, firewall running, guest broadcasting NetBIOS name queries during the scan | TCP: nothing open, 1,113 filtered; no ICMP reply; **UDP 137 answered 60 of 60 probes**. (The probe restarts the firewall after its broker case; `audit-kx-up-03` did not yet and is kept as a failed attempt.) Disk `ab4609bf…` |

Cause of the firewall failure, from `W/import-check-01/report.json`: `ipnat.sys`
imports `KeFlushQueuedDpcs` from the kernel. The same check shows `srv.sys` and
`srvsvc.dll` need `RtlIpv4AddressToStringExW` and `http.sys` needs five more
kernel exports; those are not provided.

## Hardened configuration on the combined base

`vm/security_lab.py launch --name <run> --mode up|mp|tcg --kernel kx01 --winlogon
W/reference/winlogon-build10.exe --ai-build W/ai-native-11/build --role harden
--build W/native-06/build`, then `wait --marker XP25_SEC_SCAN_WINDOW_OPEN`,
`scan <run> hardened`, `wait --ui-shutdown-after XP25_SEC_SUITE_DONE`,
`vm/security_results.py <run>`. The guest installs the tools, applies the
baseline, restarts itself, and then runs verify, audit, probe, the scan window,
the drift test, the AI suite, the compatibility suite and a final verify.

| Gate | `harden-up-04` | `harden-mp-03` | `harden-tcg-02` |
| --- | --- | --- | --- |
| role / mode | harden / up | harden / mp | harden / tcg |
| guest requested shutdown | pass | pass | pass |
| xp25 winlogon logon each boot | pass | pass | pass |
| no winlogon failure record | pass | pass | pass |
| suite completed | pass | pass | pass |
| ai suite 55 cases | pass | pass | pass |
| ai provider 7 cases | pass | pass | pass |
| established compatibility suite | pass | pass | pass |
| no failed probe case | pass | pass | pass |
| disabled remote registry refuses unchanged probe | pass | pass | pass |
| administrator can reenable and baseline reapplies | pass | pass | pass |
| tools installed | pass | pass | pass |
| baseline applied without failure | pass | pass | pass |
| baseline verified after restart | pass | pass | pass |
| baseline verified after workload | pass | pass | pass |
| verify records all ok | pass | pass | pass |
| managed services disabled and stopped | pass | pass | pass |
| fewer services running | pass | pass | pass |
| security probe ordinary account | pass | pass | pass |
| security probe restricted token | pass | pass | pass |
| security probe administrator | pass | pass | pass |
| security probe no unexplained skip | pass | pass | pass |
| probe case audit records account management | pass | pass | pass |
| probe case audit records failed logon | pass | pass | pass |
| probe case disabled service does not start | pass | pass | pass |
| probe case administrator cannot open winlogon desktop | pass | pass | pass |
| probe case run as ordinary account | pass | pass | pass |
| probe case wrong password rejected | pass | pass | pass |
| audit report completed read only | pass | pass | pass |
| firewall reports enabled | pass | pass | pass |
| audit finds no high severity issue | pass | pass | pass |
| audit detects deliberate changes | pass | pass | pass |
| audit clean after repair | pass | pass | pass |
| nothing reachable from the network | pass | pass | pass |
| scan ran while guest was up | pass | pass | pass |
| **all gates** | **pass** (34) | **pass** (34) | **pass** (34) |
| frozen disk SHA-256 | `b66745f88679…` | `5797d5609901…` | `f6b349f77958…` |

In each of the three runs `XP25Sec apply` changed 62 items, found 19 already
compliant and failed none; `verify` then reported 0 deviations in 90 items
before the restart, after it, and after the whole workload. The probe ran 70
ordinary-account, 72 restricted-token and 36 administrator cases without a
failure (3 observations of NT 5.1 defaults; 2 cases not run because the
snapshot and the optional agent policy key did not exist yet). Running Win32
services went from 39 to 34; the five baseline services that had been running
(`ERSvc`, `PolicyAgent`, `RemoteRegistry`, `WebClient`, `wuauserv`) were
stopped. The scan found no open TCP port (1,113 filtered), no UDP answer, 0 of
60 name-service probes answered while the guest broadcast, and no ICMP echo
reply. The audit reported no high-severity finding, one medium (the audit
policy change made by `apply` itself) and 13 low.

Earlier hardened runs, kept:

| Run | Outcome |
| --- | --- |
| `harden-up-01` (MinGW tools, AI build 10) | Found two defects: a key the tool had just created was owned by the administrator account, so the restricted token could write it (fixed: created keys are owned by Administrators); the lab ran the AI probe outside `C:\xp25\ai` (fixture corrected). Disk `3396d4b5…` |
| `harden-up-02` (MinGW tools, AI build 10) | 31 of 33 gates. One AI provider case (`provider_reconfigured_wrong_secret`) failed while two build-VM guests were running on the host; it passed in every run made with no other guest running. Disk `64405486…` |
| `harden-mp-01` (native tools, AI build 10) | All 34 gates of that time. Disk `bf1cd10a…` |
| `harden-up-03`, `harden-mp-02` (native tools `sec-native-03`, AI build 11) | All 34 gates of that time, including the broker case. Disks `3ab1b447…`, `06e26752…` |
| `harden-tcg-01` (same, TCG) | 33 of 34: AI 55/0 and 7/0, probe without failures, compatibility passed, but **UDP 137 answered** the scan. This exposed the firewall's broadcast-response window; the rule, the repeated probe and the broadcasting scan window were added afterwards. Disk `503190a0…` |
| `image-install-01`, `proof-up-01`, `proof-mp-01`, `rollback-up-01` | First image (`1c55d9ea…`), built before that rule; its runs passed the gates of that time. Superseded and kept |

## Hardened engineering image

`W/image-02/XP25-Security-Baseline.qcow2`, SHA-256
`6da7d04ed4f2f768d390be875228643648a7a36801e4bfe37854fdf8d7ee45d9`, 9,674,686,464 bytes,
standalone (no backing file), read-only.

Build: run `image-install-02` (single-vCPU KVM) boots an overlay of the previous
verified image `XP25-AI-Engineering.qcow2` (`ec22f45b…be2a`) with these files
written offline, each recorded with its hash in `inputs.json`: `winlogon.exe`
(XP25 Winlogon build 10, `e3a9cdca…df93`; the original is kept as
`recovery-winlogon.exe`), `xp25krnl.exe` (relinked kernel `b9531947…809d9`), the
five AI build 11 binaries, and the installer payload in the XP25 profile. In
the guest, the suite copies the tools to `C:\Program Files\XP25\Security`,
runs `XP25Sec apply`, restarts, verifies, records the reference snapshot,
deletes every test payload and its own work directory, and the guest is shut
down from the Start menu. `build/security_package_image.py` then flattens the
frozen overlay (`e567a83e5925…`) with a reflink copy, `qemu-img commit`,
`compare` ("Images are identical.") and `check`. All 11 gates of the
install run passed. An offline listing of the image (`W/image-02-inspect`)
shows no `xp25sec-*` payload, an empty Startup folder, no test profile, and
the expected hashes of the installed tools, AI binaries, Winlogon and kernel.

The image records what was changed inside itself, in
`C:\WINDOWS\XP25\Security`: `baseline-backup.txt` (every original value),
`install-plan.jsonl`, `install-apply.jsonl`, `install-services-before.jsonl`,
`install-verify.jsonl`, `install-audit.jsonl` and `audit-snapshot.txt`.

### Independent cold boot and complete suites on the image

Each run is a fresh overlay of the standalone image with only the probes
staged; nothing is installed. Two-vCPU runs add the multiprocessor kernel and
HAL to the overlay, as in every earlier XP25 matrix. The suite verifies the
baseline, runs the audit and the probe, the scan window, the drift test, the
AI suite, the compatibility suite and a final verify, then powers off.

| Gate | `proof-up-02` | `proof-mp-02` | `proof-tcg-03` |
| --- | --- | --- | --- |
| role / mode | proof / up | proof / mp | proof / tcg |
| guest requested shutdown | pass | pass | pass |
| xp25 winlogon logon each boot | pass | pass | pass |
| no winlogon failure record | pass | pass | pass |
| suite completed | pass | pass | pass |
| ai suite 55 cases | pass | pass | pass |
| ai provider 7 cases | pass | pass | pass |
| established compatibility suite | pass | pass | pass |
| no failed probe case | pass | pass | pass |
| disabled remote registry refuses unchanged probe | pass | pass | pass |
| administrator can reenable and baseline reapplies | pass | pass | pass |
| baseline verified after restart | pass | pass | pass |
| baseline verified after workload | pass | pass | pass |
| verify records all ok | pass | pass | pass |
| managed services disabled and stopped | pass | pass | pass |
| fewer services running | pass | pass | pass |
| security probe ordinary account | pass | pass | pass |
| security probe restricted token | pass | pass | pass |
| security probe administrator | pass | pass | pass |
| security probe no unexplained skip | pass | pass | pass |
| probe case audit records account management | pass | pass | pass |
| probe case audit records failed logon | pass | pass | pass |
| probe case disabled service does not start | pass | pass | pass |
| probe case administrator cannot open winlogon desktop | pass | pass | pass |
| probe case run as ordinary account | pass | pass | pass |
| probe case wrong password rejected | pass | pass | pass |
| audit report completed read only | pass | pass | pass |
| firewall reports enabled | pass | pass | pass |
| audit finds no high severity issue | pass | pass | pass |
| audit detects deliberate changes | pass | pass | pass |
| audit clean after repair | pass | pass | pass |
| nothing reachable from the network | pass | pass | pass |
| scan ran while guest was up | pass | pass | pass |
| **all gates** | **pass** (32) | **pass** (32) | **pass** (32) |
| frozen disk SHA-256 | `76ac85f75626…` | `fa279e0f4ace…` | `13ab6118bea1…` |

In each of the three runs `verify` reported 0 deviations, the probe ran 71
ordinary-account, 73 restricted-token and 36 administrator cases without a
failure, the AI suite passed 55/0 and 7/0, and the scan found nothing
reachable (1,113 TCP ports filtered, no UDP answer, 0 of 60 name-service
probes answered, no ICMP echo reply).

The audit on the image compares against the reference snapshot recorded at
build time and, in each of these runs, reports the lab's own Startup fixture
as `config.added` (medium) — the test harness's persistence is what it is
built to notice. `proof-tcg-02`, a first TCG proof made while two other guests
were running, passed 30 of 32 gates: the AI interface case
`clippy_minimizes_to_tray` failed once (54/1). It is kept; `proof-tcg-03` is
the same run with no other guest on the host.

### Rollback

Run `rollback-up-02` (overlay of the image, single-vCPU KVM): `XP25Sec rollback`
restored every record (97 records: 54 registry values, 24 access-control records, 18 services and the audit policy, none failed), the guest restarted, and afterwards
`status` reported no baseline, `verify` reported deviations again, the service
start types equalled the ones recorded before hardening, the five originally
running services ran again and the unchanged Remote Registry probe passed. The
scan shows the original firewall behaviour back as well: the name service
answered 57 of 60 repeated probes again while the guest broadcast, and
unsolicited TCP stayed filtered, because the kernel export that lets the
firewall run is not part of the tool's rollback. All 12 gates passed
(disk `54018861894c…`).

Rollback to the previous verified image is unaffected: `XP25-AI-Engineering.qcow2`
was re-hashed after every staging and packaging step and is unchanged
(`ec22f45b…be2a`); the runs of this milestone that boot overlays of it
(`pre-up-02`, the `audit-*` and `harden-*` runs) are that proof.

### Preservation

- `Source/` was not modified (the kernel export is applied to the build VM's
  disposable copy; `git status` shows no change under `Source/`).
- `XP25-AI-Engineering.qcow2`, `XP25-Winlogon-Engineering.qcow2` and the
  `XP25-AI` virtual machine with its overlay, Guacamole connection and network
  were not touched; lab guests are named `xp25sec-*` and run in their own
  network namespaces without an uplink.
- Every lab disk is frozen read-only; failed and superseded runs are kept with
  a `failure.json`.

## Not tested

- Any network other than the isolated namespace; real hardware; other NIC
  models; the image in the libvirt VMs.
- Known NT 5.1 kernel exploits against the source-built kernel (assumed to
  work; see the threat model).
- Games and third-party applications beyond the established suites. The
  AutoRun, Internet-zone and broadcast-response trade-offs are described, not
  exercised with real titles.
- Fast User Switching, Remote Desktop, printing, and domain membership.
- The rollback of a single item, and `rollback --from <file>`.


# Milestone 8.1 — stabilization, firewall verification and final acceptance

Evidence is under `.work/security81-20261112/` (`W81`); the Milestone 8 root
`W` is read-only input. Runs are in `W81/runs`, build-VM runs in
`.work/boot-debug-20261022/sec81-*`. Every run boots a fresh overlay of a
hash-verified image; failed runs are kept with a `failure.json`.

## What the framework gained

| Piece | Role |
| --- | --- |
| Guest-requested observations | The guest writes `XP25_HOST_REQUEST=<kind>:<label>` to COM1 and waits with `security_probe.exe hostwait <label>` until the observer has finished (an outbound HTTP poll of `10.25.0.1:8081`, which the guest firewall does not filter). Guest steps and host probes are ordered without fixed waits. Kinds: `scan`, `ports`, `udp-expiry`, `udp-series`, `watch-start`/`watch-stop` (`vm/security_network.py`) |
| Packet capture as evidence | QEMU records every frame of the guest's network card. The observer brackets each observation with marker frames (EtherType 0x88B5, addressed so the guest's card drops them); `vm/security_pcap.py` splits the capture by them and counts, per port, the observer's SYNs and datagrams and the guest's SYN-ACKs, resets and replies *to those attempts*, the guest's own broadcasts and unaddressed DHCP requests. Gates check the sockets' view and the wire's view |
| Test listener | `security_probe.exe listen 5025 <dir> broadcast`: TCP banner and UDP echo, and a broadcast from its UDP port every half second, so "filtered" can be told from "nothing listens" and the firewall's reply-to-broadcast window is exercised independently of NetBIOS |
| `fwcheck` | Guest view of the firewall: service and IPNAT driver running, start type, profile policy values, and who may control the service (its DACL) |
| New probe cases | 7 firewall-service rights, 7 firewall keys, the IPNAT device, `netsh`/`net stop` as the unprivileged user (decided by policy and service state afterwards), 21 autostart/hijack keys, 12 system files, 6 system directories, `boot.ini`, `ntldr`, All Users Startup/Start Menu/Desktop, 13 broker requests and a pipe-name takeover attempt (ordinary account and restricted token), the broker serving an ordinary user, service restoration after each context |
| `desktop` and `apps` probe modes | A standard user's own session (profile, shell identity, Luna, files, ClippyAI, RoverAI, broker, IE, programs, shutdown right) and the programs and games installed with Windows (window, responsiveness, close, crash detection through Windows Error Reporting) |
| Roles | `firewall`, `standard-user`, `ai-repeat` (rounds with ClippyAI and RoverAI ended and fixtures removed between them), `image-upgrade`, `apps` (`vm/security_fixtures.py`) |
| Lab options | `--image m8|m81`, `--ai-probe`, `--host-load CPUS` (`vm/host_load.py`: busy processes at an 80 % duty cycle and a 64 MB write–fsync–delete loop, bounded in time), typed multi-account logon plan |
| Offline and build tools | `vm/security_kernel_check.py` (installed kernel, exports, every driver's kernel imports, firewall services), `build/compare_pe.py` (relink comparison), `vm/native_build_run.py` (one native build end to end), `vm/security_evidence.py` (storage inventory and reclaim) |

Host tests: `tests/test_security.py` 19 tests (fixture ordering, request
parsing, capture accounting, kernel-check PE parsing, the new rule kind and its
scope), `tests/ai_core.c` with the two-tier broker list.

## Task 1 — Windows Firewall

**Was the kernel change kept?** Yes. `vm/security_kernel_check.py` read the
Milestone 8 image offline (`W81/kernel-check-m8-image-03`): `boot.ini` boots
`xp25krnl.exe`, byte-identical to the relinked kernel `b9531947…809d9`, which
exports `KeFlushQueuedDpcs` (ordinal 526, in `PAGE`). All 101 kernel imports of
`ipnat.sys` resolve; no driver on the image imports the kernel by ordinal. The
review of the change is in the [baseline document](security-baseline.md#kernel-change-review-milestone-81).
The firewall service is `SharedAccess` (svchost `netsvcs`, automatic, depends on
Netman and WMI); its driver is `IPNAT` (demand start, loaded by the service).
(Two earlier attempts of this check, `kernel-check-m8-image` and `-02`, are kept:
defects of the new script, no guest involved.)

**First check on the Milestone 8 image (`fw-m8-up-01`).** The firewall ran and
filtered, an administrator could open and close a port, disable and enable it,
stop and start the service. Four weaknesses: (1) the service's DACL let Power
Users stop and pause it (NT 5.1 default); (2) the ordinary account and the
restricted token could create files in `%SystemRoot%\Tasks`; (3) the SYSTEM
broker stopped the DNS Client and the Task Scheduler for an ordinary user and
served the restricted (browser-contained) token at all; (4) probing UDP 137
continuously across a restart, the name service answered from about 18 s into
the restart on: NetBT registers names by broadcast from UDP 137 before the
firewall service has applied its policy, and the conversation opened in that
window stayed open. All four are fixed in 8.1 (baseline version 2, AI build 13).

**How the role tests the firewall.** The guest starts a test listener (TCP
banner, UDP echo, a broadcast from its UDP port every half second), then for
each state asks the observer for a targeted observation and waits for it to
finish: TCP 5025, 135, 139, 445, a UDP echo from the listener, 20 NetBIOS
node-status probes and ICMP echo. Each stage is judged twice: by the
observer's sockets, and by the capture segment between its marker frames (the
observer's SYNs reached the guest; the guest sent no SYN-ACK, reset, reply or
echo reply to them). States: no exception; an administrator opens TCP and UDP
5025 with `netsh`; removes them; the ordinary-account and restricted-token
attempts; the administrator disables and re-enables the firewall; stops and
starts the service; the guest restarts, watched continuously (every half
second: TCP 135/139/445/5025, UDP 137 from one held socket and from a new one,
UDP 5025, ICMP echo); after the restart.

| Gate | `fw-up-03` | `fw-mp-01` | `fw-tcg-01` |
| --- | --- | --- | --- |
| role / mode | firewall / up | firewall / mp | firewall / tcg |
| guest requested shutdown | pass | pass | pass |
| xp25 winlogon logon each boot | pass | pass | pass |
| no winlogon failure record | pass | pass | pass |
| suite completed | pass | pass | pass |
| firewall service and driver running first boot | pass | pass | pass |
| firewall service and driver running after restart | pass | pass | pass |
| firewall still running after unprivileged attempts | pass | pass | pass |
| unprivileged firewall attempts all refused | pass | pass | pass |
| no firewall case skipped | pass | pass | pass |
| administrator firewall commands succeed | pass | pass | pass |
| baseline verified after administrator restored it | pass | pass | pass |
| new connections blocked as soon as exception is removed | pass | pass | pass |
| removed exception state ends for every peer | pass | pass | pass |
| listener blocked without exception | pass | pass | pass |
| listener blocked after unprivileged attempts | pass | pass | pass |
| listener blocked after administrator reenabled firewall | pass | pass | pass |
| listener blocked after service restart | pass | pass | pass |
| listener blocked after guest restart | pass | pass | pass |
| explicitly permitted port works | pass | pass | pass |
| same listener reachable when administrator disables firewall | pass | pass | pass |
| same listener reachable when service is stopped | pass | pass | pass |
| nothing answered at any moment of the restart | pass | pass | pass |
| capture confirms restart window | pass | pass | pass |
| guest listener log matches observer | pass | pass | pass |
| guest listener received nothing after expiry | pass | pass | pass |
| listener broadcast rate bounded | pass | pass | pass |
| every observation completed | pass | pass | pass |
| **all gates** | **pass** (27) | **pass** (27) | **pass** (27) |
| frozen disk SHA-256 | `62276b3ad574…` | `3fae3b8f4f19…` | `f75d7f186094…` |

What the runs show:

- **Starts and runs:** `fwcheck` on both boots and after the unprivileged
  attempts — service running with a process, automatic start, IPNAT running,
  `EnableFirewall=1` in both profiles, no broadcast replies, no control right
  for Users or Power Users.
- **Filters what it should:** without an exception the listener is filtered
  on TCP and UDP while it is listening (the guest's own log shows no
  connection), as are 135/139/445, the name service (0 of 20) and ICMP echo.
- **Permits what it should:** with the administrator's exception the same
  listener answers on TCP and UDP and the guest's log records exactly those
  connections; 135/139/445 stay filtered and the name service silent.
- **Removal:** new TCP connections are refused as soon as the exception is
  removed. A datagram sent right after the removal by the peer that had used the
  exception was still answered (`immediately_after_removal: response`): the
  firewall keeps state for a UDP port that has just sent to that peer. After
  150 s without traffic, neither that peer nor an address the guest has never
  seen got an answer, and the listener received nothing from the new address.
  This is the Windows Firewall's own UDP state handling, recorded rather than
  changed.
- **Administrator control:** `netsh firewall set opmode DISABLE` and stopping
  the service open exactly what one expects (listener, 135, 139, name service,
  ICMP echo); `ENABLE` and starting the service close it again; the baseline
  verifies clean afterwards.
- **Unprivileged control refused:** the ordinary account and the restricted
  token cannot pause, re-secure, take ownership of, delete or fully open the
  service, stop or reconfigure IPNAT, write any firewall key or the group-policy
  key, open the IPNAT device for writing; `netsh firewall set opmode DISABLE`,
  `netsh firewall add portopening` and `net stop SharedAccess` leave the policy
  and the service as they were; the broker refuses.
- **Restart:** nothing answered at any moment of the watched restart (TCP,
  UDP 137 from a held and from a new socket, UDP 5025, ICMP), the capture
  shows the guest's DHCP request inside the watched window, and enforcement is
  back after the restart.

Kept failed runs: `fw-up-01` (first 8.1 candidate; 20 of 26 gates, invalid
because the test listener echoed its own broadcasts endlessly and the capture
reader missed DHCP requests sent from 0.0.0.0 — both lab defects, fixed).
`fw-up-02` (first candidate, AI build 13) passed 27 of 27 and is superseded by
the runs on the final image.

## Task 2 — privilege boundaries and the broker

Every Milestone 8 finding was re-tested on the final image from three
contexts. In each proof run the probe passed 149 ordinary-account, 151 restricted-token and 36
administrator cases with no failure:
`ue51sp3.dll`, kernel, HAL, NTFS driver and `XP25Broker.exe` cannot be opened
for writing or re-secured; the broker's service key and policy keys cannot be
written or re-secured; protected directories, 40 machine-wide registry
locations, 12 system files, 6 system directories and the All Users folders
refuse the ordinary account and the restricted token; process injection into
LSASS, Winlogon, services, CSRSS and the broker is refused; the administrator
keeps every control (writes to `system32` and `HKLM\SOFTWARE`, full SCM
access, debug privilege).

**Broker audit.** The authorization and dispatch code
(`components/xp25-agent/broker/broker.c`, `xp25_policy.c`, the client in
`win_service.c`) was reviewed end to end; the four weaknesses and their fixes
are described in the [threat model](security-threat-model.md#2-privilege-escalation).
The broker offers one operation (start/stop/restart a service), decided only
from its own machine policy and the caller's token, never from the request.
The probe's 13 requests — firewall, Security Center, Event Log, the broker
itself, DNS Client, Task Scheduler, starting the disabled Remote Registry, a
non-service operation, a path as a service name, malformed and oversized
requests — are all refused from the ordinary account (`permission_denied`,
`broker_unsupported`, `broker_malformed`) and from the restricted token
(`broker_refused` for every one), while the same ordinary account and a
standard user's own desktop session can still restart the print spooler. The
pipe name cannot be taken over (every `CreateNamedPipe` refused with access
denied while the broker serves a stream of requests), and the broker keeps
running afterwards. ClippyAI's service tool goes through the same client.

## Task 3 — ClippyAI and RoverAI stability

**The two Milestone 8 failures** (`clippy_minimizes_to_tray` in `proof-tcg-02`,
`provider_reconfigured_wrong_secret` in `harden-up-02`) were both a fixed
sleep followed by a single check in the probe, after a *posted* message:
2 s after `SC_MINIMIZE`, 1.5 s after the settings dialog's OK. The work behind
OK includes two calls into LSA (Data Protection, then Credential Manager). The
`harden-up-02` serial record shows the dialog still open at the check and gone
a moment later (`settings_not_accepted` with an empty result text). Both
failures happened while other guests ran on the host. The probe now sends
these requests with `SendMessageTimeoutW`, which returns when the window
procedure has finished the step, waits for the key field to hold every typed
character before confirming, decides the settings outcome by the dialog
disappearing or showing an error, and closes the Explorer bar by waiting for
the band to hide (bounded); every step's time is recorded as an `ai_timing`
note. Expected results are unchanged (55 + 7 cases).

**Reproduction attempt with the old probe** on the Milestone 8 image:

- `ai-old-load-up-01`: under an unbounded load (6 busy cores and 230 GB of
  synchronous writes in 2 hours on the volume holding the guest disk) the guest
  slowed by two orders of magnitude (RoverAI index 629 s instead of 6 s,
  windows missing their 30 s budgets); round 3 did not finish. Kept as the
  record of what such contention does; it is not a moderate load.
- `ai-old-load-up-02`: under the moderate load (4 processes at 50 % duty, about
  10 MB/s of synchronous writes, `vm/host_load.py` defaults) the two Milestone 8
  failures did **not** recur in three rounds — but `rover_rename_reflected`
  failed in rounds 1 and 3.

**A real RoverAI defect.** Round 3's files show the search right after a forced
re-index loading a saved index that still had `home-notes.txt` and lacked
`house-notes.txt`, although the re-index (`index-2.json`) had seen the rename.
The background indexer (`RoverAI /background`) checked whether to save *before*
applying change notifications that had already arrived, waited for the store
lock while the forced re-index held it, and then saved its older in-memory
index over the fresh one: whoever saved last won. Fixed in AI build 14
(`components/roverai/indexer/rover_win.c`): the watcher applies every delivered
change before deciding to save, and when the saved index changed since the
watcher last wrote or adopted it, it rescans every root before saving instead
of overwriting another writer's listing (`rover_watch_adopt_store`).

**Repeated runs on the final image** (new probe, AI build 14, three rounds
each, ClippyAI and RoverAI ended and fixtures removed between rounds, moderate
host load for the whole run):

| Gate | `ai-load-up-01` | `ai-load-mp-01` |
| --- | --- | --- |
| role / mode | ai-repeat / up | ai-repeat / mp |
| guest requested shutdown | pass | pass |
| xp25 winlogon logon each boot | pass | pass |
| no winlogon failure record | pass | pass |
| suite completed | pass | pass |
| every round completed | pass | pass |
| clippyai and roverai ended before every round | pass | pass |
| round 1 ai suite 55 cases | pass | pass |
| round 1 ai provider 7 cases | pass | pass |
| round 2 ai suite 55 cases | pass | pass |
| round 2 ai provider 7 cases | pass | pass |
| round 3 ai suite 55 cases | pass | pass |
| round 3 ai provider 7 cases | pass | pass |
| no failed ai case | pass | pass |
| timings recorded | pass | pass |
| **all gates** | **pass** (14) | **pass** (14) |
| frozen disk SHA-256 | `5c8ca4958f5f…` | `9c673699994d…` |

Measured step times (`ai_timing`, milliseconds, maximum over the rounds):
clippy minimize processed 328, clippy restore processed 62, settings secret typed 110, settings ok processed 109 — a fraction of the former fixed 2 s and 1.5 s. The Milestone 8 failures
happened while other guests ran on the host; under the moderate load used here
the steps finish so quickly that only much heavier contention would have
exceeded the old waits (not reproduced). The proof runs add one more AI round
each without load, including TCG (TCG maxima: clippy minimize processed 422, clippy restore processed 140, settings secret typed 109, settings ok processed 156).

**Classification.** The Milestone 8 failures: a probe synchronization defect
exposed by host contention, fixed in the probe. `rover_rename_reflected`: an
application defect exposed by host load, fixed in RoverAI. Remaining risk: under
extreme host I/O contention (`ai-old-load-up-01`) bounded waits of the suite are
exceeded; that is an environmental limit of the lab, not a guest defect.

## Task 4 — standard-user desktop

Role `standard-user`: the administrator creates `xp25user` (member of Users
only, random 14-character password known only to the run), makes MSGINA offer
it and restarts; the standard user logs on, runs the desktop checks, the
programs and games, and restarts the computer; logs on again, repeats the
desktop checks and powers the computer off.

| Gate | `std-up-08` | `std-mp-01` | `std-tcg-01` |
| --- | --- | --- | --- |
| role / mode | standard-user / up | standard-user / mp | standard-user / tcg |
| guest requested shutdown | pass | pass | pass |
| xp25 winlogon logon each boot | pass | pass | pass |
| no winlogon failure record | pass | pass | pass |
| suite completed | pass | pass | pass |
| standard account created as user only | pass | pass | pass |
| logons in planned order | pass | pass | pass |
| standard user desktop first logon | pass | pass | pass |
| standard user programs and games | pass | pass | pass |
| standard user no program crash beyond the unhardened base | pass | pass | pass |
| standard user desktop after restart | pass | pass | pass |
| standard user restarted the computer | pass | pass | pass |
| standard user powered the computer off | pass | pass | pass |
| **all gates** | **pass** (12) | **pass** (12) | **pass** (12) |
| frozen disk SHA-256 | `1075e5121c83…` | `cf098a6e5f7b…` | `83d7154258ea…` |

On both logons the standard user (not an administrator or power user) gets
its own profile and registry hive on the Default desktop, Explorer runs under
its own token with the Luna visual style, file operations in its profile work
and `Program Files` refuses writes, Notepad, Calculator and Solitaire start and
close, IE8 opens a local page and closes (on the first start IE8 shows its
"Set Up Windows Internet Explorer 8" wizard and, once that is cancelled, asks
whether to close both tabs — both recorded), ClippyAI starts offline, reads the
event log and runs a read-only command and exits, RoverAI builds the user's own
index and finds the user's file, the broker restarts the print spooler for the
user and refuses to stop the DNS Client, the user may query services and holds
the shutdown right; then the 14 programs and games, restart and power-off.
No operation needed administrator rights. No XP25 component needed a
permission change for a standard user.

**Account switching after a logoff (not a permission problem; pre-existing).**
After a logoff the XP25 Winlogon's logon dialog shows both fields grey and
empty and nothing typed becomes visible. This is the defect the Winlogon
milestone already records ([known gaps](winlogon-desktop-session.md#known-gaps-and-defects)):
the edits are enabled and accept input but do not paint after a logoff (the
8.1 runs agree: Winlogon logs both edits as enabled). It occurs on the 8.1
candidate (`logon-focus-01`, logoff during start-up; `logon-focus-02`, 60 s
after the desktop settled) and on the unhardened combined base
(`logon-focus-base-01`), so the baseline does not cause it. The lab could not
log on a second account through that dialog reliably: blind keys landed in
the wrong field, or — with no field focused — acted as the dialog's shortcuts
(S = Shut Down, which restarted or powered off the guest in `std-up-02` and
`std-up-03`). Whether a person can switch accounts by typing blind was not
established. The standard-user role therefore switches accounts with a
restart, where the dialog paints and the password field has the focus.
Kept lab failures on the way: `std-up-01` to `-06` (the above, a 16-character
password made `net user /add` ask a question, the console-program case ended
the Startup script, IE8's first-run tab) — see each `failure.json`, and the
`correction.json` of the `logon-focus-*` runs.

**Conclusion.** A standard account works as the daily XP25 desktop, including
the AI components, the browser and the built-in programs, with account
switching done by a restart. Recommended as the default once the post-logoff
painting defect is fixed; the production `XP25-AI` account was not changed.

## Task 5 — coverage

| Area | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| Firewall: start, filtering, permitted port, removal, administrator control, unprivileged refusal, restart window, reboot persistence (`fw-*`) | Pass (`fw-up-03`) | Pass (`fw-mp-01`) | Pass (`fw-tcg-01`) |
| Protected files, registry ACLs, service control, broker escalation, persistence locations (probe in `proof-*`, `fw-*`) | Pass | Pass | Pass |
| Hardened configuration after restart and workload; drift detection (`proof-*`) | Pass | Pass | Pass |
| Rollback of the security configuration | Pass (Milestone 8, `rollback-up-02`) | Pass (`rollback-mp-01`) | Not run |
| Custom Winlogon logon, `licdll` admission, Explorer identity (every run) | Pass | Pass | Pass |
| Explorer/Luna, ClippyAI, RoverAI: AI suite 55 + provider 7 (`proof-*`) | Pass | Pass | Pass |
| AI suite repeated three times under moderate host load (`ai-load-*`) | Pass | Pass | Not run |
| Networking (network probe, isolated HTTP/DNS) and compatibility CD (`proof-*`) | Pass | Pass | Pass |
| Standard user: logon, desktop, files, AI, browser, programs, restart, power-off (`std-*`) | Pass (`std-up-08`) | Pass (`std-mp-01`) | Pass (`std-tcg-01`) |
| Programs and games installed with Windows (`proof-*` as administrator, `std-*` as standard user) | Pass, Hearts crash pre-existing | Pass, Hearts crash pre-existing | Pass, Hearts crash pre-existing |
| Shutdown and restart (guest-requested power-off every run; restarts in `fw-*`, `std-*`) | Pass | Pass | Pass |
| Logoff and logon as another account without a restart | **Not established**: the fields do not paint after a logoff (known XP25 Winlogon defect); the lab could not log on through them | Not run | Not run |

| Gate | `proof-up-01` | `proof-mp-01` | `proof-tcg-01` |
| --- | --- | --- | --- |
| role / mode | proof / up | proof / mp | proof / tcg |
| guest requested shutdown | pass | pass | pass |
| xp25 winlogon logon each boot | pass | pass | pass |
| no winlogon failure record | pass | pass | pass |
| suite completed | pass | pass | pass |
| ai suite 55 cases | pass | pass | pass |
| ai provider 7 cases | pass | pass | pass |
| established compatibility suite | pass | pass | pass |
| no failed probe case | pass | pass | pass |
| disabled remote registry refuses unchanged probe | pass | pass | pass |
| administrator can reenable and baseline reapplies | pass | pass | pass |
| baseline verified after restart | pass | pass | pass |
| baseline verified after workload | pass | pass | pass |
| verify records all ok | pass | pass | pass |
| managed services disabled and stopped | pass | pass | pass |
| fewer services running | pass | pass | pass |
| security probe ordinary account | pass | pass | pass |
| security probe restricted token | pass | pass | pass |
| security probe administrator | pass | pass | pass |
| security probe no unexplained skip | pass | pass | pass |
| probe case audit records account management | pass | pass | pass |
| probe case audit records failed logon | pass | pass | pass |
| probe case disabled service does not start | pass | pass | pass |
| probe case administrator cannot open winlogon desktop | pass | pass | pass |
| probe case run as ordinary account | pass | pass | pass |
| probe case wrong password rejected | pass | pass | pass |
| audit report completed read only | pass | pass | pass |
| firewall reports enabled | pass | pass | pass |
| audit finds no high severity issue | pass | pass | pass |
| audit detects deliberate changes | pass | pass | pass |
| audit clean after repair | pass | pass | pass |
| legacy programs and games start and respond | pass | pass | pass |
| no program crash beyond the unhardened base | pass | pass | pass |
| nothing reachable from the network | pass | pass | pass |
| capture shows guest broadcasting during scan | pass | pass | pass |
| capture confirms guest sent no answer | pass | pass | pass |
| **all gates** | **pass** (35) | **pass** (35) | **pass** (35) |
| frozen disk SHA-256 | `5533b9d2cbdb…` | `3eaa3b1334ef…` | `c00904c561c4…` |

**Games.** No game fixtures existed in the repository. The games installed
with Windows were used: Solitaire, FreeCell, Spider Solitaire, Minesweeper,
Hearts and 3D Pinball start, draw a responsive window and stay up; all but
Hearts close normally. **Microsoft Hearts crashes** when its opening "Hearts
Network" dialog is closed — the same on the unhardened combined base
(`apps-base-up-01`), so it is not caused by the baseline; the cause was not
investigated. Third-party games: Not tested (none are installed).

## Task 7 — the final image

`W81/image-81-02/XP25-Security-Baseline-8.1.qcow2`, SHA-256
`501c79862d41824a2748c96f5b4715f22ba25443630cb1e3ff0c13674999fda4`, 9,674,752,000 bytes, standalone, read-only.

**Lineage:** `XP25-AI-Engineering.qcow2` (`ec22f45b…be2a`) → Milestone 8
`XP25-Security-Baseline.qcow2` (`6da7d04e…45d9`, unchanged) → this image.
**Built by** run `upgrade-up-02` (single-vCPU KVM, 14 gates passed): a fresh overlay of the
Milestone 8 image with AI build 14 written offline over the five XP25 AI files
(existing files keep their protected ACLs) and the 8.1 tools staged in the XP25
profile; in the guest the suite verified the Milestone 8 baseline (clean),
replaced `XP25Sec.exe` and `XP25Audit.exe`, ran `apply` (only the five new items
changed; their originals were added to the existing backup), restarted,
verified, recorded a new reference snapshot, kept the upgrade record beside the
original install record (`upgrade-81-*.jsonl` next to `install-*.jsonl`),
removed every test payload and was shut down from the Start menu.
`build/security_package_image.py` then flattened the frozen overlay
(`cf541528c5a0…`) onto a reflink copy of the parent: `qemu-img compare` "Images
are identical.", `qemu-img check` clean. The kernel, HAL and Winlogon are the
Milestone 8 ones (`b9531947…`, `12b0847d…`, `e3a9cdca…`).

**Contents that changed from Milestone 8:** XP25Sec `e645be7a…c021`, XP25Audit
`972e9c0f…82cc` (native NT build `sec81-native-01`, `/W4 /WX`); AI build 14
(native build `sec81-ai-native-14`): xp25agent.dll `458c088f…0de80`,
XP25Broker.exe `7e157693…a4ce`, ClippyAI.exe `f45299f1…1876`, RoverAI.exe
`4501cb0d…198e`, RoverAIBand.dll `ed6b9257…e789`; baseline version 2.

**Reproducible creation:** `build/prepare_security.py`, `build/prepare_ai.py`,
`vm/native_build_run.py` (two builds), `build/security_collect_native.py`,
`build/ai_collect_native.py`, then `vm/security_lab.py launch --image m8 --role
image-upgrade --build <tools> --ai-build <ai build>`, `wait --ui-shutdown-after
XP25_SEC_SUITE_DONE`, `vm/security_results.py`, `build/security_package_image.py
--name XP25-Security-Baseline-8.1.qcow2`. The image bytes are not bit-for-bit
reproducible (guest time stamps, logs, the snapshot), the procedure and its
inputs are; the manifest records every input hash.

**Validation on fresh overlays of it** (every Task 1–5 run above uses this
image): cold boot with the UP kernel/HAL pair under one-vCPU KVM and TCG and
the MP pair under two-vCPU KVM; XP25 Winlogon logon with `licdll` admission and
Explorer identity on every boot; AI and compatibility suites; firewall
enforcement; security regressions; guest-requested power-off; reboot
persistence (firewall and standard-user roles restart and re-check); rollback
on two-vCPU KVM.

**Rollback on two-vCPU KVM (`rollback-mp-01`, 12 gates passed):** `XP25Sec rollback`
restored 102 records (55 registry values, 28 access-control records, 18 services
and the audit policy), none failed; after the restart `status` reported no
baseline, `verify` reported deviations again, the service start types equalled
the ones recorded before Milestone 8, the unchanged Remote Registry probe passed
and the original firewall behaviour was back (the name service answered 60 of
60 repeated probes while the guest broadcast; the test listener answered 16 of
20 datagrams after its own broadcasts; unsolicited TCP stayed filtered, because
the kernel export that lets the firewall run is not part of the tool's
rollback). Rollback to an image is unaffected: the Milestone 8 image and the
earlier verified images are unchanged.

The first 8.1 candidate (`W81/image-81`, `cc0453e8…bf8e`, AI build 13) is kept,
marked superseded: AI build 14 fixes the RoverAI race found on it.

## Task 8 — storage and evidence

`vm/security_evidence.py` first took an inventory (`W81/evidence-inventory-01.json`):
it read the header of every QCOW2 file on the volume (386) to map backing
chains, and measured shared and exclusive space with `btrfs filesystem du`.

| Kind | What | Decision |
| --- | --- | --- |
| Accepted images | Milestone 8 `image-02` (`6da7d04e…`), 8.1 `image-81-02` (`501c7986…`) | Kept unchanged; shared with each other and with the reference base through reflinks |
| Recovery and reference images | `reference/XP25-AI-Engineering.qcow2` (`ec22f45b…`), the two build-VM bases, the superseded `image-01` and `image-81` | Kept: they back 19, 10, 7, 3, 3 overlays and are needed for reproducible builds; never compressed (that would un-share their extents) |
| Frozen run disks (passed, failed, superseded) | 58 exclusive overlays in `W/runs`, `W81/runs` and the build-VM runs | Kept and compressed in place (btrfs zstd), each hashed before and after: identical; read-only mode restored |
| Redundant screenshots | 337 `.ppm` files with a `.png` twin | Deleted after a pixel-for-pixel comparison with the twin (310.6 MB) |
| Logs, captures, results, `failure.json`, manifests, build outputs | All | Kept |
| Disposable copies | None found: FUSE mount points are empty files, extraction directories are small records | Kept |

Nothing outside the evidence roots depends on any file that was changed; no
QCOW2 file was deleted. Free space on the volume rose from 49.06 GB before the
reclaim to 90.31 GB after it (`W81/df-*-reclaim.txt`, `W81/evidence-reclaim-01.json`
lists every action). The volume is shared with the other worktrees, so this
41.25 GB is an upper bound for what the reclaim freed; btrfs does not report
per-file compressed sizes to an unprivileged user. The images and the Winlogon
engineering image were re-hashed after the reclaim and are unchanged.


# Milestone 8.2 — historical CVE remediation

Milestone 8.2 (`xp25-cve`) audits seven historical Windows XP CVE groups and
fixes the confirmed, fixable ones at the source level. Its evidence root is
`.work/cve82-20261112/` and its records are [historical-cve-audit.md](historical-cve-audit.md)
and [historical-cve-remediation.md](historical-cve-remediation.md). The one
installed fix (MS04-011 in `lsasrv.dll`) ships in `XP25-CVE-Hardened-8.2.qcow2`,
which passes the full regression suite above (`cve82-proof-up-01`, 35 gates) and
the MS04-011 guest checks under one-vCPU KVM, two-vCPU KVM and TCG
(`cve82-verify-up-02`/`-mp-01`/`-tcg-01`, `cve82-image-up-01`).
