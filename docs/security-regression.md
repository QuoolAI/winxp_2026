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

