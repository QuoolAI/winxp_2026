# Milestone 9: MerlinAI — self-repairing XP25 with a shared builder VM

Worktree `xp25-merlin` (branch `xp25-merlin`, from `xp25-modernization` `fa387ec3e`).
Evidence root `.work/merlin-20261121/` (`E`); native build-VM runs under
`.work/boot-debug-20261022/merlin-native-*`; builder VM under
`.work/merlin-builder-vm-20261121/`. `Source/` is not touched.

## Original checkpoint (2026-11-21)

The later model-investigation and image-validation record below supersedes
the unconfigured-provider and unpackaged-client limitations in this table.

| Stage | Observed | Not yet |
| --- | --- | --- |
| 9A client and diagnostics | Lab suite 22/22 under KVM UP, two-vCPU KVM and TCG (native build 06); native build 08 (Security Center fix) 24/24 under UP, MP and TCG | Build 08 not packaged into an image |
| 9B builder VM | `MerlinAI-Builder` (separate KVM guest) accepts authenticated jobs from several installations, builds natively in a nested build VM, keeps installations apart (Phase 11) | No model provider configured: the offline rule-based investigator decided every job |
| 9C personalized image and tests | Candidates tested before/after; after-tests pass under nested KVM UP, two-vCPU KVM and TCG; `fixed_verified` | Only MerlinAI's own components are rebuilt automatically |
| 9D user-approved replacement | Apply and Roll Back on `XP25-MerlinAI-Demo` with health check; three agent defects found in the demonstration, fixed and kept (Phase 12) | Health check is minimal; overlay chains are never merged |

At this checkpoint no AI model had investigated a problem. A real model run
is recorded below. Until 2026-11-24 the builder rebuilt only MerlinAI's own
programs. Since then it also rebuilds the XP25 Winlogon, AI and security
components and the kernel, each behind a control build that must reproduce the
installed binary; the first real OS defect repaired is the Filter Manager that
did not load ([whole-OS record](merlinai-whole-os.md)). The XP25-Winlogon-Fix VM
runs MerlinAI since 2026-11-23 (enrolled, health reported).

## What MerlinAI is

MerlinAI replaces XP's retired Microsoft error reporting, Security Center and
Automatic Updates pages with an on-demand repair loop that the user drives:

```text
XP25 guest                          host (KVM)                         MerlinAI Builder VM (separate KVM guest)
----------                          ----------                         ------------------------------------------
MerlinCrash  "Send to MerlinAI" --.
MerlinSvc    local discovery ------> queue (local only)
MerlinAI.exe "Build an Update" ---> merlin_relay.py (no secrets) ---> API (control plane): auth, quotas, job store
             "Review Build"    <---                              <--- runner (execution plane):
                                                                        workspace -> investigate -> MinGW check ->
                                                                        native NT build (nested VM) -> candidate
                                                                        QCOW2 + update content -> tests (nested VMs)
             "Apply Update" ------> merlin_deploy_agent.py  <------- update content (agent credential)
MerlinSvc    health report -------> keeps or restores the image
```

* The user always starts a build and always approves its application.
  "Send to MerlinAI" only queues (and, with consent, transfers) a report.
* Nothing is downloaded from a central update service; there are no signed
  update packages. Each build is made for one installation from source.
* No AI-generated change reaches a running system silently: the deployment
  agent switches the VM's disk only after the user's signed approval names the
  exact update content (`delta_sha256`) that the builder recorded and tested.

## Components

| Component | Where | Role |
| --- | --- | --- |
| `MerlinClient.dll` | `components/merlin/client` + portable core `components/merlin/core` | Queue, collector, configuration and credentials, authenticated HTTP to the builder and the deployment agent, redaction |
| `MerlinCrash.exe` | `components/merlin/crash` | AeDebug post-mortem handler: the new error-report dialog |
| `MerlinAI.exe` | `components/merlin/app` | "MerlinAI — System Health & Updates" (four sections), installer, Merlin character |
| `MerlinAI.cpl` | `components/merlin/cpl` | Control Panel entry, replaces Security Center and Automatic Updates |
| `MerlinSvc.exe` | `components/merlin/svc` | LocalSystem service: health report after every boot, local collection |
| `MerlinTest.exe` | `components/merlin/testapp` | Controlled test component with a reproducible defect (demonstration) |
| MerlinAI Builder | `components/merlin/builder/merlin_builder` | API (`server.py`), job runner (`runner.py`, `pipeline.py`), investigation (`investigate.py`) |
| Builder VM | `components/merlin/builder/deploy` | `builder_vm.py` (host), `install-builder.sh` (in the VM), systemd units, `merlin-builder` filter |
| Relay | `components/merlin/host/merlin_relay.py` | Guest HTTP to the builder (TLS to a remote builder); holds no secrets |
| Deployment agent | `components/merlin/host/merlin_deploy_agent.py` | User-approved disk switch with health check and rollback |
| Lab | `vm/merlin_lab.py`, `vm/merlin_network.py`, `vm/merlin_jobtest.py`, `vm/merlin_native_build.py` | Guest tests, job tests, native builds |

The client does not use `xp25agent.dll`, ClippyAI or RoverAI. It compiles
the portable SHA-256 of `components/xp25-agent/llm` into itself (a source
dependency, not a runtime one) and has its own copy of the Microsoft Agent
interface layout.

## Phase 1: consolidation and the M9 baseline

* Branches: `xp25-modernization` (`fa387ec3e`) already contained every verified
  line (`xp25-nt` ⊂ security ⊂ cve ⊂ winlogon-ui ⊂ modernization; the
  `xp25-browser` commits are patch-equivalent to `xp25-nt`'s). The only
  verified change not integrated was `xp25-ai` `18ebc97f9` (the XP25 gateway's
  service unit, installer and `xp25-gateway-only` filter). It is merged as
  `ab860bf60`; the two documentation conflicts kept both entries. Host suite
  after the merge: 162 tests, 16 skipped for private inputs.
* No packaged engineering image carried the verified post-8.2 components
  together. `build/package_image.py` (now accepting `/Program Files/XP25/`
  targets and AI collection records) built **`XP25-M9-Baseline.qcow2`
  `a3bde9b2836aad585fe7dc95cc056a7845e7f1940f95e40a0ba381c322d15e08`** from the
  accepted 8.2 image `5a84781f…eada` by replacing nine files offline, each
  checked against its installed hash and its native build record:
  * `winlogon.exe` `e3a9cdca…` → `020eaf40…` (R-0, screen savers and idle lock);
  * `win32k.sys` `b28afb2f…` → `f698e04d…`, `user32.dll` `a51976dd…` → `4cccacd3…`,
    `gdi32.dll` `09698075…` → `13e538d3…` (R-1);
  * AI build 17: `xp25agent.dll` → `e4638922…`, `ClippyAI.exe` → `2d1555db…`,
    `RoverAI.exe` → `c1352991…`, `RoverAIBand.dll` → `480d6d5b…`,
    `XP25Broker.exe` → `e328cc76…`.
* `XP25-M9-MerlinAI.qcow2` `0f04a4381c6aedd6956a3b5d0a09e2e539947395ef94ef0f52598beca9314d32`
  is that baseline with MerlinAI installed by its own installer
  (`vm/merlin_lab.py --scenario install`, run `m9-merlin-install-01`, committed
  into a reflink copy by `build/merlin_package_image.py`), endpoints preset to
  the host services, no credentials, revision `XP25-M9-MerlinAI-1`. It is the
  builder's baseline and the demonstration VM's disk.

## Phase 4: Windows XP error reporting, as found

| Piece | In XP25 | Provenance |
| --- | --- | --- |
| `kernel32!UnhandledExceptionFilter` | Reads `AeDebug` (`Debugger`, `Auto`) through win.ini mapping; if `Auto=1` and the debugger is not `drwtsn32`, it starts the debugger directly; otherwise it loads `faultrep.dll` and calls `ReportFault` (`base/win32/client/thread.c` 1880–2080) | **Source-built** (1106) |
| `faultrep.dll` | `ReportFault` → `dwwin.exe -x -s` (DW shared memory) or manifest mode; logs "Application Error" 1000 / "Application Hang" 1002 / "System Error" 1003 (`admin/pchealth/client/faultrep`) | Binary (SP3) |
| `dwwin.exe` | The "Send Error Report / Don't Send" dialog, posting to `watson.microsoft.com` | Binary, no source |
| `drwtsn32.exe` | Default AeDebug debugger (`-p %ld -e %ld -g`, `Auto=1`) on the image | Binary |
| `dumprep.exe`, `ersvc.dll` | Queued and kernel-fault reporting at the next logon; ERSvc is disabled by the security baseline | Binary |
| `savedump.exe`, `CrashControl` | Kernel dumps (`%SystemRoot%\Minidump`), "Save Dump" 1001 | Binary |
| Registry on the 8.2 image | `PCHealth\ErrorReporting` `DoReport=1`, `ShowUI=1` | — |

**Integration chosen:** the documented post-mortem debugger hook. `MerlinAI.exe
/install` sets `AeDebug\Debugger` to `"…\MerlinCrash.exe" -p %ld -e %ld` with
`Auto=1`, so kernel32 never loads faultrep for user-mode crashes and no other
dialog is touched. Microsoft reporting is turned off (`DoReport=0`,
`ShowUI=0`), which also silences dwwin for hangs and kernel faults; kernel
dumps and the "Save Dump" events are unchanged and MerlinAI discovers them.
MerlinCrash writes the same "Application Error" 1000 event faultrep would, so
event-log based tools keep working; the collector counts a crash once even
though both its report and its event exist. Every replaced value is saved
first and `/uninstall` restores it (verified).

The dialog shows the application, error type, a short summary, report
details (the redacted text that would be sent), **Send to MerlinAI** and
**Don't Send**, plus two separate consents: transfer to the builder now, and
include the memory dump. Send queues the report; it never starts a build.
Crashes of processes without the INTERACTIVE group or running as SYSTEM,
LocalService or NetworkService get no dialog (a SYSTEM process must not put
UI on the user's desktop); they are queued silently. If MerlinCrash itself
crashed, an inherited environment variable stops it from debugging itself.

## Phase 5: local discovery

`MerlinCollect` (run by MerlinSvc, at administrators' logon and from the
window) reads the Application, System and Security logs with
`OpenEventLogW`/`ReadEventLogW`, the XP25 Winlogon's `C:\xp25\native-winlogon.log`
and the crash reports, with per-log bookmarks (record number and time; a
cleared log restarts). The portable classifier keeps only failures:

| Source | Kind |
| --- | --- |
| Application Error 1000, DrWatson 4097 | crash (bucket = the five strings of event 1000) |
| Application Hang 1001/1002 | hang |
| Service Control Manager 7000/7001/7009/7011/7022/7023/7024/7031/7034 | service, or **security** (critical) for firewall, Security Center, event log, IPsec, cryptographic, audit and XP25 services |
| SCM 7026 | driver |
| Save Dump 1001, System Error 1003 | kernel (critical) |
| EventLog 6008 | shutdown |
| Disk, atapi, Ntfs, ftdisk, cdrom errors | storage |
| Winlogon log `*_failed`, `*_rejected`, `*_unsupported`, rollbacks, shell restarts | winlogon |
| Security 516/517 (audit loss/cleared) | security |
| any other error record; warnings only from XP25/MerlinAI sources | event |

Informational and success-audit records are never problems; a mistyped
password (529) is not; nothing is labelled a vulnerability. Problems are
keyed by a SHA-256 signature, occurrences are kept by reference (newest 32 by
reference, all counted), first/last times, status, whether the user submitted
it and the build job. Discovered problems are never transmitted
automatically. A standard user sees and removes only their own reports (the
queue's DACL); system-wide problems, builds and updates need an administrator.

## Phase 6: Security Center and Automatic Updates

`wscui.cpl` (Security Center), `wuaucpl.cpl` (Automatic Updates), `wscsvc` and
`wuauserv` are SP3 binaries. MerlinAI registers `MerlinAI.cpl` ("MerlinAI
Health and Updates") and turns off Security Center's antivirus, firewall and
update notifications. The Security Center service, the Windows Firewall
(SharedAccess, verified running) and auditing are unchanged. Automatic
Updates stays disabled as the 8.x baseline left it, with the `NoAutoUpdate`
and `NoWindowsUpdate` policies added.

**Corrected during the demonstration.** The first release hid the two applets
only with the machine-wide "don't load" list and registered MerlinAI in
category 10. The 9A gates enumerate the Control Panel folder, and they passed.
But in the category view the "Security Center" tile still opened Windows
Security Center (screens `demo-01/05b-category.png`). A disposable overlay
(`experiments/seccenter-01`, `result.json`) showed why:

* the image's shell32 treats the Security Center tile as a direct link to
  `wscui.cpl`. Registering a second applet in category 10 does not turn it into
  a category page, so MerlinAI was never listed there;
* the tile disappears only when `wscui.cpl` is restricted by the documented
  "Hide specified Control Panel items" policy (`DisallowCPL` = 1 and
  `...\Policies\Explorer\DisallowCpl`). shell32 reads that list from
  `HKEY_CURRENT_USER` only (`cputil.cpp` `IsNameListedUnderKey` in the
  reference tree);
* category value names are matched after environment expansion, so the first
  release's `C:\WINDOWS\system32\MerlinAI.cpl` name was valid. The fault was the
  category, not the name.

Native build 08 therefore registers MerlinAI in category 5 (Performance and
Maintenance) under `%SystemRoot%\system32\MerlinAI.cpl`. It also writes the
policy into every user hive (`mc_policy.c`): loaded hives, the other
ProfileList profiles through `RegLoadKey`, and Default User for future
accounts. Each hive keeps its previous `DisallowCPL` so `/uninstall` restores
it, and only MerlinAI's own list entries are removed. The guest probe now reads
MerlinAI's category the way the category view does
(`IShellFolder2::GetDetailsEx`), and the 9A lab gates the policy in the
logged-on user's and Default User's hives.

Found on the way: the image's `shell32.dll` does not read the SP2 `Cpls` key
at all (the string is absent), and `control.ini [MMCPL]` is per user, so the
applet is installed in `system32`; the shell also drops `&` from applet names.
A guest probe (`tests/guest/merlin_probe.c`) enumerates the Control Panel
folder through `IShellFolder` and gates the replacement.

## Phase 2 / 9B: the MerlinAI Builder VM

`MerlinAI-Builder` is its own libvirt guest (`builder_vm.py provision`):
Ubuntu 24.04 cloud image `noble-server-cloudimg-amd64.img` (checksum verified
at download), 6 vCPUs with nested SVM (`host-passthrough`), 8 GiB, a system
disk, a 157 GiB data disk at `/srv/merlin`, and two **read-only** virtio
disks. The serial `merlin-baseline` carries the approved XP25 image
(`XP25-M9-MerlinAI.qcow2` `0f04a438…4d32`) and `merlin-buildvm` the frozen
NT 5.1 build VM chain. The builder sees the images only as these disks: it has
no host path, libvirt socket, SSH key or production disk. Its NIC filter
`merlin-builder` admits the API port and the hypervisor's SSH for
administration.

`builder_vm.py bootstrap` sends a Git bundle of one approved commit,
without `Source/`. `install-builder.sh` makes it the immutable bare baseline
repository, owned by root and read-only for the service account. It also
creates the tools checkout, QCOW2 wrappers whose backing files are the
read-only disks, the MinGW toolchain, reference files (guest system DLLs for
import checks, the verified MP kernel and HAL, linker maps of the baseline's
MerlinAI build), and the API and runner units as `merlinsvc`. The current
baseline snapshot is `c88f545de`, the source snapshot of `39c4e3848`.
Bring-up failures are kept on the builder: job `J-20261121-221611-99acd9`
failed because `cc1` could not load `libisl.so.23`, and
`J-20261121-221731-31e2de` because the native media were outside the tools'
`.work`.

Per job, the runner (one job at a time, with a 15 GiB disk reserve and recovery
of interrupted jobs) does the following:
1. clones the baseline at the approved commit into `jobs/<J>/workspace`;
2. investigates;
3. cross-compiles the change in a user namespace without network;
4. builds natively in a NIC-less overlay of the build VM (nested KVM);
5. writes the candidate as an overlay of the installation's baseline with only
   the rebuilt files replaced offline, recording each file's installed hash as
   `expected_before`;
6. publishes the update content (`xp25-merlin-delta/1` manifest plus files,
   SHA-256 bound to the job);
7. tests in NIC-less overlays.

Installations, reports and jobs live in per-installation directories with
mode 0700, under quotas: 1 MiB requests, 8 MiB dumps, 500 reports, 256 MiB
per installation, 2 open jobs.

## Phase 7: investigation

`investigate.py` gives the investigator only restricted tools. It can list,
read and search the workspace, map a crash offset to a function through the
build's linker map (`symbol_at`), read a component's provenance
(`components.json`: XP25 source, Microsoft source-built, or binary-only),
replace text in files under `components/`, run the MinGW check and conclude.
There is no shell. Diagnostics are passed as delimited untrusted data, and a
report's text never becomes a command. The OpenAI Responses and Anthropic
Messages tool loops were initially tested against local mock servers
only. **At the 2026-11-21 checkpoint no model provider was configured, so
those jobs were decided by the labelled offline rule-based investigator.**
The later real-provider runs are recorded below. It repairs one fault class, an unchecked NULL from a lookup
located through the crash offset, and classifies common non-XP25 causes
(third-party module, out of memory, hardware or virtual hardware) without a
change. Its conclusions say so in the build review ("Investigated by: MerlinAI
offline investigator (rule-based; no AI model was used)").

Only MerlinAI's own components are rebuilt automatically (`build: merlin`; the
2026-11-21 state, superseded by recipes on 2026-11-24, see
[merlinai-whole-os.md](merlinai-whole-os.md)).
A justified change elsewhere is reported as not built, and binary-only
components are reported as such. AI changes never reach the baseline: they
exist only in the job's workspace and update content.

## Phase 8 / 9C: the personalized candidate image

A candidate is `jobs/<J>/image/candidate.qcow2`, an overlay whose backing
file is the installation's baseline wrapper. The rebuilt files are copied in
offline, and each one's previous hash is checked against the baseline first.
The image revision becomes `<base revision>+<job>` (`C:\xp25\image-revision.txt`).
The deployment agent applies the same files to a new overlay of the
**installation's own current disk**, so documents, settings and programs on that
disk stay. A file whose installed hash differs from `expected_before` stops
the update, and the VM restarts unchanged. XP25 keeps user data on the system
volume. No separate data volume was introduced: the single-disk overlay route
is what was verified (Phase 12).

## Phase 9: tests

`vm/merlin_jobtest.py` boots NIC-less overlays and logs on through the XP25
Winlogon. A staged Startup script runs the component's reproduction check from
`components.json` (for MerlinTest.exe: `MerlinTest.exe /check`, which reports
its own unhandled exception). It records `XP25_JOBTEST_*` markers on COM1 and
turns the guest off from the Start menu. Per job:
* **before** on the baseline, KVM UP: the reported problem must reproduce;
* **after** on the candidate, KVM UP, two-vCPU KVM (verified MP kernel and HAL)
  and TCG: the check passes, plus the regression gates (boot to the logon
  prompt, logon completed, desktop started, checks ran, `MerlinAI.exe
  /status` OK, normal turn-off).

Problem results:
* `fixed_verified`: reproduced before and passing after in every mode;
* `not_reproducible`: did not reproduce before;
* `unresolved`: otherwise;
* `not_applicable` / `mitigated`: from the investigation.

A job is ready only with at least one `fixed_verified` problem and every
regression gate passing. Failed jobs keep all evidence and are never retried
automatically.

## Phase 10 / 9D: Apply Update and Roll Back

The host deployment agent (`merlin_deploy_agent.py`, a systemd user service of
the libvirt user) serves only the domains in its configuration. Apply, in
order:
1. authenticate the installation, with the deployment key the builder never
   has;
2. take the installation's exclusive lock;
3. check that offline application works at all (added after the first demo
   failure);
4. fetch the job record with the agent's own builder credential (it must
   belong to this installation, be ready, and name the approved
   `delta_sha256`);
5. download and verify the update content;
6. answer 202. The guest shuts itself down; the agent waits for `shut off`.
7. create a new overlay on the current disk and write the files offline after
   the `expected_before` checks;
8. make the replaced disk read-only;
9. change only the disk source in the domain definition and start it;
10. wait for MerlinSvc's authenticated health report with the new revision
    (Winlogon, event log and RPC running, volume not dirty).

If the VM does not start or report healthy, the agent restores the previous
system on a fresh overlay. Roll Back is a separate, explicitly confirmed
request. It starts a **fresh overlay on the previous disk**, so the newer
image stays intact (changes made after the update stay there, not visible
after rolling back), and is checked by the same health gate. Nothing is ever
deleted: failed attempts' overlays and every domain definition the agent
replaced are kept in its state directory.

## Phase 11: several installations

Every request names its installation and is HMAC-authenticated with that
installation's key. Jobs, reports and update content are looked up only
within the installation: the demonstration installation gets 404 for the
self-test installation's job, and its job list shows only its own job
(`demo-01/builder-job-*.json`). Each job has its own workspace, temporary
directory, disks, logs and base image record. The runner never lets one job's
output into another's workspace. The agent credential reads only the jobs of
the installations it serves. The API (control plane) and the runner
(execution plane) are separate processes and units. Cancellation and discard
are per job and interrupted jobs are marked failed at runner start
(implemented; not exercised in a recorded run).

## Phase 12: end-to-end demonstration (2026-11-21)

Demonstration VM `XP25-MerlinAI-Demo` (created by `enroll_vm.py create`): a
reflink copy of `XP25-M9-MerlinAI.qcow2` `0f04a438…4d32`, 1 vCPU, 1 GiB,
RTL8139 on `XP25-Isolated` (10.25.0.27, filter `xp25-merlin`: relay 8740 and
agent 8746 on 10.25.0.1 only). It was enrolled offline with installation
`xp25-merlin-demo`, its builder key and a new deployment key. Host:
`merlin-relay` (10.25.0.1:8740 → `http://192.168.122.223:8740`) and
`merlin-deploy-agent` (10.25.0.1:8746). Driven only by keyboard through
libvirt (`vm/libvirt_ui.py`). Screens and journals are in
`.work/merlin-20261121/demo-01/`.

| Step | Observed |
| --- | --- |
| Run `MerlinTest.exe` | MerlinAI Error Report: MerlinTest.exe 1.0.0.1, access violation (0xc0000005) at `MerlinTest.exe+0x1495`, reading 0x0 (`03`) |
| Tick "Transfer…" (no dump), Send to MerlinAI | "Transferred 1 report(s) … No build was started" (`04`); relay log: `POST /merlin/v1/reports` 202 for `xp25-merlin-demo`; stored under that installation only |
| Control Panel | Category "Security Center" opened **Windows Security Center** (`05b`): the gap described in Phase 6. MerlinAI was reached through Classic View (`06a`, `07`) |
| Problem Queue | The crash first among 21 collected problems; ticked (`08`, `08a`) |
| Build an Update | Confirmation listing only that problem; job `J-20261121-223005-f06e40` started (`09a`, `10`); Merlin animates |
| Builder | Offline investigator: NULL from `find_value()` used in `load_display()`; native build; candidate (MerlinTest.exe and the revision file); before-UP reproduced; after-UP/MP/TCG passed; problem `fixed_verified`; 22 test results; ready about 15 minutes after the request |
| Guest notices | Merlin: "Build … is now ready" (`11`) |
| Review Build | Status, investigator (offline, no AI model), conclusion, change, file, rebuilt component, tests, limitations, risks, user data, rollback, candidate hashes (image `a3b5d4d7…`, update content `a2c84ef2…`), READY TO APPLY: yes (`12c`–`12e`) |
| User document | `My Documents\merlin-demo-note.txt` written (`13`) |
| Apply Update #1 (approval `d9e6f3ad…`) | Accepted and staged; guest shut down normally; **offline application failed** (`fusermount3: mount failed: Operation not permitted`, the unit's NoNewPrivileges). The agent kept the disk and restarted the VM. Failure kept. |
| Agent fixed | No NoNewPrivileges; offline check before shutdown; attempt-numbered overlays (commit `829956389`) |
| Apply Update #2 (approval `a9c0555e…`) | Guest shut down; two files written into `XP25-MerlinAI-Demo.J-20261121-223005-f06e40.2.qcow2` after hash checks; base made read-only; domain switched and started; health report `XP25-M9-MerlinAI-1+J-…f06e40` 13 s after start; `apply_healthy`; builder records `applied` |
| Updated system | Same `MerlinTest.exe` and `merlintest.ini`: message box, no crash (`20`); `merlin-demo-note.txt` intact; revision file updated (`21`) |
| Roll Back #1 (approval `ee6af5c6…`) | **Failed**: the agent booted the previous disk directly; it was the read-only backing file of the newer image, QEMU could not open it, and the start error bypassed the restore, so the VM stayed off. Recovered with the journaled operator command `restore-current` (updated overlay); no data lost (the guest had shut down normally) |
| Agent fixed | Rollback/restore on a fresh overlay, start failure → restore, previous revision recorded from health reports |
| Roll Back #2 (approval `46131306…`) | Guest shut down; `XP25-MerlinAI-Demo.rollback.qcow2` on the previous disk; started; health report `XP25-M9-MerlinAI-1`; state recorded correctly, but the agent then logged `operation_error` (two threads shared `state.json.tmp`). Fixed with unique temporary files (same commit) |
| Rolled-back system | Revision `XP25-M9-MerlinAI-1`; `merlin-demo-note.txt` present; `written-after-update.txt` not visible (kept in the updated image) (`30`); `MerlinTest.exe` crashes again at `+0x1495` (`31`) |

The production VMs (XP25-AI, XP25-Winlogon-Fix, XP25-Security-8.1, …), the
frozen images and the builder's baseline were not modified. The demonstration
VM, its overlays and the agent's journal are its own.

## Model investigation and VM-image validation (2026-11-22/23)

Evidence `xp25-merlin/.work/merlin-vm-20261122/` (`W`).

### Model investigation

The user's OpenAI key was installed on the builder with `builder_vm.py provider
--kind openai --model gpt-4.1`. The key was typed into the user's own terminal,
travelled over SSH into `/etc/merlin-builder/provider.key` (root:merlinsvc
0640), and was accepted by the provider (HTTP 200). First model-driven job,
`J-20261122-230605-224659` (`W/ai-job/`), on the MerlinTest crash report:

* tool calls: `symbol_at` (MerlinTest.exe+0x1495 → `load_display`),
  `component_info`, `search_code`, four `read_file`s, `edit_file`,
  `compile_check`, `read_file`, conclusion;
* change: `if (!t) t = "XP25 Display Greeting";` after the `Title` lookup (the
  offline investigator had chosen an empty string);
* native build, candidate image, defect reproduced before the change;
  afterwards the check passes (`title_length=21`) and every regression gate
  passes under nested KVM UP, two-vCPU KVM and TCG; `fixed_verified`, ready.

The review states the investigator (`MerlinAI model investigator (OpenAI
Responses API, model gpt-4.1)`). The model saw only the redacted report and its
restricted tools.

### Several baselines, per-installation credentials

An installation is built and tested on its own system image. `builder_vm.py
add-baseline` copies a frozen image (checked against its manifest), attaches
it to the running builder as another read-only virtio disk (serial
`merlin-bl-NAME`), and puts its source snapshot on its own branch of the
immutable repository. It also installs the image's linker maps and records
the baseline in `/etc/merlin-builder/baselines.d/` (kept across
re-bootstraps). `bootstrap --tools-commit` updates the builder's own scripts
without changing any baseline's source: the M9 snapshot reproduced exactly
as `c88f545de`. The deployment agent can hold a separate builder credential
per installation, which reads only that installation's jobs. The builder VM
got four spare PCIe root ports (its definition was redefined and restarted
once; both definitions are kept in `vm-01/`).

### Defects found on the way (fixed; failures kept)

| Found by | Defect | Fix |
| --- | --- | --- |
| `proof` of the first VM image (`wf-proof-up-01`, 32/35) | `C:\xp25\image-revision.txt` modifiable by non-administrators (`acl.xp25_lab`). `ntfscp` gives a file it **creates** no security descriptor at all; a **replaced** file keeps its descriptor (checked on a scratch overlay) | The revision file is created in the guest; the builder refuses a baseline without it; the deployment agent refuses any update that would create a file, before the guest shuts down |
| the same mechanism | `enroll_vm.py` stages a script **with keys** that every local account can read until the first XP25 logon deletes it | `enroll_vm.py --keyboard`: types `MerlinAI.exe /configure` into an administrator console through libvirt, keys not logged, nothing written to the guest's disk; the offline method warns |
| job test of the VM image (`wf-image01-up`) and the builder's nested TCG test (`J-20261122-232024-d33440`) | Winlogon's `core_ready` lost on COM1 → the harness never logged on | `merlin_jobtest.py`: all markers also go to `C:\xp25\jobtest.log`; logon also starts on Winlogon's visible-dialog record; gates read the guest's logs from the frozen overlay |
| screen-saver probe of the VM image (`wf-ss-up-02` 4/10; unchanged disk `wf-ss-ref-01` 10/10) | MerlinSvc wrote a COM1 line on every 30-s health-report retry (30 per boot on an unenrolled image), crowding out the Winlogon records the probe paces itself by | MerlinSvc writes the first result, changes, success and giving up (native build 09) |
| cancelling the hung nested TCG test | the test VM kept running: QEMU runs in its own session | `kill_job_guests`: a cancelled or timed-out step also stops the job's QEMU guests by name |
| nested TCG test of `J-20261123-005336-fc7b5d` | `tasklist` (WMI) did not answer in time: `desktop started` failed, job not ready | the Explorer check retries for a minute |
| two-vCPU job test | a relative `--mp-kernel` path resolved after `chdir` | paths resolved first |
| browser regression of image-03 (`wf03-browser2-up`) | Supermium hit its known intermittent CHECK (`chrome.dll+0x842214`) while restarting, and the MerlinAI dialog kept the crashed `chrome.exe` attached until answered; Dr. Watson, which the VM used before, ended it silently | MerlinCrash ends the crashed program (after capturing report, stack, dump and event) before it shows the dialog (native build 10) |
| 9A of native build 10 under two-vCPU KVM (`merlin-9a-mp-04`, 21/24) | the harness typed into the crash dialog on the capture record, which precedes `end_target()`'s wait of up to 10 s; Alt+T/Alt+S reached the details window and the report was later answered Don't Send | MerlinCrash writes `XP25_MERLIN_CRASH_DIALOG_READY` once its dialog is initialized; the harness waits for it (native build 11, `108ad0451`, [record](merlin-dialog-readiness.md)). A repetition of build 10 (`merlin-9a-mp-05`) passed 24/24: timing in the harness, not the product |
| 9A of native build 11 under TCG (`dialog-ready-tcg-01`, 20/24) | Windows refused the crash dialog the foreground (flashing taskbar button): since build 10 the crashed program, stopped under the debugger, is ended before the dialog asks for it. The harness's Enter then opened Internet Explorer from the desktop | the dialog takes the foreground, then ends the program, before it is visible, and reports `foreground=1/0`; the harness never types into a dialog without the foreground (native build 12) |
| enrolling the XP25-Winlogon-Fix VM | an existing VM enrolled into the agent had no recorded current disk: the guest showed *current system unknown* and `restore-current` had nothing to start | `merlin_deploy_agent.py adopt ID REVISION` after the first health report; `enroll_vm.py` now prints this step |

The packaged M9 image `XP25-M9-MerlinAI.qcow2` and the demonstration VM still
carry the first, offline-created revision file. It has no access control there.
The demo VM and the M9 baseline were left as they are.

### XP25-Winlogon-Fix VM image

Reference: the VM's own disk, shut off, frozen as
`W/reference/XP25-Winlogon-Fix.f5da32b5.qcow2` (`f5da32b5…54a6`; it differs from
the last packaged image `9e1e8f08…`, so the user's changes since then are
kept). MerlinAI native build 09 was installed by its own installer
(`wf-merlin-install-03`: every step 0; user policy loaded=1 offline=1
default_user=1 failed=0) → `W/image-03/XP25-Winlogon-Fix-MerlinAI.qcow2`
**`c5d5eca1a326e6693f7680a81ec7bb73774605bda6d4e544689e1811d4b7ed9a`**, revision
`XP25-Winlogon-Fix-MerlinAI-1`. Images 01 (`4240dc03…`) and 02 (`269d57c6…`) are
superseded by the two defects above and kept.

| Test on image-03 | Result |
| --- | --- |
| Job test KVM UP / two-vCPU KVM / TCG: boot, logon, desktop, MerlinTest defect present as shipped (exit 2), Security Center policy present, MerlinSvc and firewall running, `MerlinAI.exe /status`, Start-menu turn-off | 6/6, 6/6, 6/6; MerlinSvc one COM1 line per boot |
| Security `proof` | 34/35: the four USB drivers the unchanged disk already had (as before MerlinAI) |
| Screen-saver probe | 10/10 |
| Two-account switch oracle | 9/9 |
| Browser regression matrix through a gateway | Superseded by image-04 results below |
| Builder job on baseline `xp25wf3` (this image), model gpt-4.1, `J-20261123-011458-fc9b9c` | ready, `fixed_verified`, all gates under nested UP/MP/TCG |

Image-04 packages native build 10, including the crashed-process termination
fix: `W/image-04/XP25-Winlogon-Fix-MerlinAI.qcow2`, SHA-256
`378e9edd71f9fc3435800ca3b0ad856a08f435e3a6b09e66d2dc32fee3e58183`.
Its parent is the frozen VM reference above. Offline installed-file hashes are
in `image-04/manifest.json`; no source-kernel rebuild is implied.

| Test on image-04 | Recorded result |
| --- | --- |
| Native boot, logon, desktop, MerlinAI status, checks and normal turn-off | 6/6 under UP, MP and TCG (`wf-image04-*`) |
| Security `proof` (`wf-proof-up-04`) | 34/35; only the four inherited USB-driver audit findings remain |
| Screen saver (`wf-ss-up-04`) | 10/10 |
| Two-account switch (`wf-2acct-up-04` **failed**, kept; repetition `wf-2acct-up-05`) | First run: 3 of 5 switches painted. At cycle 4 the Found New Hardware wizard was in front of the desktop and took the switch keys; cycle 5 never reached a painted dialog (`failure.json`; no crash, one MerlinSvc COM1 line). Repetition, nothing else running: 9/9 painted switches, alternating accounts, wrong password rejected |
| Browser (`wf04-browser-up`, `matrix-03`) | 23/26 aggregate checks; DevTools 11/11 and persistence pass; MSI and AI 55/0 + 7/0 pass; normal turn-off |
| Model builder job `J-20261123-020135-92f5c3`, baseline `xp25wf4` | Ready, defect reproduced before; repaired check and six regression gates pass under nested UP/MP/TCG |

The browser aggregate remains **failed**: disabled Remote Registry produces
errors 1058/1062 (case-results and exit-code gates); four explicit `not_tested`
probe cases fail the full-coverage gate. These are the same limitations as the
pre-MerlinAI browser image. The browser's known intermittent
`chrome.dll+0x842214` CHECK is not fixed by terminating crashed processes.

Native build 10's separate 9A suite passed 24/24 under UP (`merlin-9a-up-11`)
and TCG (`merlin-9a-tcg-04`). MP (`merlin-9a-mp-04`) passed 21/24: its
interactive report was not queued or transferred, and the trace records
`dont_send`. Capture completion precedes the bounded process-termination wait,
and the harness sent dialog keys before the dialog was initialized. A
repetition of build 10 (`merlin-9a-mp-05`) passed 24/24. Build 11 added a
readiness record: MP 24/24, UP 24/24, TCG **failed** 20/24 because Windows
refused the dialog the foreground. Build 12 takes the foreground before ending
the crashed program: UP 24/24, MP 24/24, TCG 24/24. Details:
[dialog readiness and foreground](merlin-dialog-readiness.md).

[Focused continuation](merlin-dialog-readiness.md).

### Deployment to the XP25-Winlogon-Fix VM (2026-11-22/23)

Evidence `W/enroll-wf/` (domain definitions before and after, agent
configuration before enrollment) and `W/deploy-01/` (screenshots, the libvirt
command journal `commands.jsonl`, disk hash). The VM's directory is `V =
xp25-winlogon-ui/.work/virt-manager-XP25-Winlogon-Fix-20261118/`.

1. With the domain shut off and its disk still `f5da32b5…54a6` (the frozen
   reference), that disk was renamed `V/XP25-Winlogon-Fix.supermium.qcow2`
   (kept) and image-04 was reflink-copied to `V/XP25-Winlogon-Fix.qcow2`
   (`378e9edd…8183`). The superseded staged copy of image-03 in `V` (hash
   checked, `c5d5eca1…`) was deleted; image-03 itself stays in `W/image-03/`.
2. `virsh nwfilter-define components/merlin/host/xp25-browser-merlin.nwfilter.xml`.
   The domain was redefined with two changes only: filter
   `xp25-browser-gateway` → `xp25-browser-merlin` (adds RELAY_PORT 8740 and
   DEPLOY_PORT 8746 on 10.25.0.1; the AI gateway 8443 and browser gateway 3128
   are unchanged) and the description.
3. First boot, 2026-11-22 18:52 PST: logon dialog (`00-boot.png`). These tools
   sent nothing further; the domain was shut down normally at 21:18 PST
   (libvirt reason `shutdown`) by a request not journaled here. The disk was
   then `d485e136…830a`, revision `XP25-Winlogon-Fix-MerlinAI-1`.
4. Enrollment, offline (not `--keyboard`): `enroll_vm.py enroll` staged
   `C:\xp25\merlin-enroll.cmd` and an XP25 Startup entry, and added the
   installation to the agent's configuration with a new deployment key and the
   per-installation builder credential `xp25-host-wf`. Until the first logon
   the staged files had no access control; the disk's only user profiles are
   `XP25` and `Administrator`, both administrators. After that logon both
   files were gone (checked read-only after shutdown). The agent's builder
   credential reads no other installation's job (404) and a wrong key is
   refused.
5. Second boot, 2026-11-23 21:05 PST. Logon as `XP25` (Enter, blank password,
   caret in the password field checked first): the Startup entry ran
   `MerlinAI.exe /configure`, and MerlinSvc's next retry delivered an
   authenticated health report 102 s after boot (agent journal 05:08:08Z).
   Restart through Start → Turn Off Computer → Restart: health report 11 s
   after boot, before any logon (05:09:43Z): revision
   `XP25-Winlogon-Fix-MerlinAI-1`, Winlogon, RPC, Event Log and firewall
   running, volume not dirty.
6. `merlin_deploy_agent.py adopt xp25-winlogon-fix XP25-Winlogon-Fix-MerlinAI-1`
   recorded the domain's disk as current (see the defect table).
7. Control Panel, classic view as this VM is set (`14`, `15`): *MerlinAI
   Health and Updates* present; no Security Center, no Automatic Updates;
   Windows Firewall present. MerlinAI (`16`–`19`): Builder and Deployment agent
   *configured*; revision shown; 20 outstanding problems from the VM's own
   event history (drivers failing to load, W32Time, SSDP, HTTP, Server,
   Computer Browser, firewall/ICS); Previous Builds empty, which the relay
   journal confirms as authenticated `GET /merlin/v1/jobs` for
   `xp25-winlogon-fix` with status 200; agent status *idle; current system
   XP25-Winlogon-Fix-MerlinAI-1; no previous system to roll back to*.
8. Start → Turn Off Computer → Turn Off: libvirt *Shutdown Finished after
   guest request*. Disk afterwards
   `55723697d22e69ae10d6d2104ef89948258f7e5699990e0b9c0d64233e7cc082`.

Not done on this VM: no update was built, reviewed, applied or rolled back
(Apply and Roll Back are shown on `XP25-MerlinAI-Demo`; the builder's model
job on this VM's baseline `xp25wf4` is above). The VM runs native build 10
(source `361a3b6d0`). Builds 11 and 12 change only MerlinCrash (readiness
record; foreground before ending the crashed program) and are not installed
on it.

## Protocols and trust

* **Guest → builder** (through the relay): XP25-MERLIN1. `GET /merlin/v1/challenge`
  issues a single-use 32-byte challenge (120 s); a request carries the
  installation id, challenge, a 16-byte nonce and
  `HMAC-SHA256(builder key, "XP25-MERLIN1\nMETHOD\npath\ninstallation\nchallenge\nnonce\nsha256(body)")`;
  every reply carries `HMAC(key, "XP25-MERLIN1-RESPONSE\nnonce\nstatus\nsha256(body)")`
  and unauthenticated replies are discarded by the client. No clock is
  needed. The C implementation and Python's `hmac` produce the same MAC.
* **Guest → deployment agent:** the same construction with the label
  `XP25-MERLIN-DEPLOY1` and a **different key** that the builder never has.
* **Agent → builder:** the agent's own builder credential, which can read only
  the jobs of the installations it serves and fetch their update content.
* Keys live in `HKLM\SOFTWARE\XP25\MerlinAI\Credentials` with a protected DACL
  (SYSTEM and Administrators). Model-provider credentials exist only on the
  builder (`/etc/merlin-builder/provider.key`).
* Integrity, not authenticity: the hashes and MACs bind what is applied to
  what the builder recorded and the user approved. They do not make the
  builder trustworthy. A compromised builder can produce a malicious update
  with correct hashes, and a user can approve it. There is no code signing
  and no central update authority, by design; the remaining defences are the
  separation of keys (a builder cannot trigger a deployment), the user's
  review, the agent's restricted operations and rollback.

## Data handling

Reports are redacted before preview and transfer (profile paths → `%USERPROFILE%`,
the account and computer names, e-mail addresses, credential-shaped
`key=value`, `Bearer` tokens, API-key and long mixed-case base64 strings; file
hashes are kept). Memory dumps stay local unless the user ticks the separate
dump consent. Reports are bounded (64 problems, 24 evidence lines of 256
characters, 32 occurrence references) and every field is validated by the
builder. The link from the guest to the relay is not encrypted; it stays on
the host's isolated bridge, and the relay uses TLS with certificate checks
for a builder elsewhere (plain HTTP only to a private address).

## Current limitations (2026-11-22/23)

* Real model investigation is recorded for the controlled MerlinTest NULL
  dereference. It does not establish repair of other defects, general kernel
  changes or third-party applications. Earlier Phase 7 results used the offline
  investigator; both histories are retained.
* Since 2026-11-24 the pipeline rebuilds MerlinAI, the XP25 Winlogon, AI and
  security components and the kernel (`base/ntos`); see
  [merlinai-whole-os.md](merlinai-whole-os.md) for what is verified. The other
  Microsoft-source components are mapped but not rebuilt; binary-only components
  cannot be. On the XP25-Winlogon-Fix baseline the installed AI components are not
  reproducible from current source, so the builder refuses to replace them.
* The original `XP25-M9-MerlinAI.qcow2` and demonstration VM retain the first
  release and the revision-file ACL limitation described above. The newer
  XP25-Winlogon-Fix image-04 contains the Control Panel fix and is the VM's disk
  since 2026-11-23. On that VM enrollment, health reports, the Control Panel
  and the builder connection are observed; Build, Review, Apply and Roll Back
  are not yet exercised there. Its 20 queued problems (the VM's own event
  history) are not MerlinAI components, so a build for them can at most
  report them.
* The source merged as of this record is native build 12; the XP25-Winlogon-Fix
  VM runs build 10 (the demo VM an older release). They differ only in
  MerlinCrash: build 10's crash dialog can come up without keyboard focus (its
  taskbar button flashes; clicking it works), and it has no readiness record.
  Moving the VM to build 12 needs a new system revision and builder baseline.
* The post-deployment health check is minimal (core services running, volume
  not dirty, reported before any logon). The reported problem is tested by
  the builder on its copy of the baseline, not again on the user's disk.
* Each rollback or restore adds an overlay. Nothing merges or prunes the
  chain, and nothing deletes old overlays.
* The deployment agent runs as a user service with `qemu:///system` access.
  It restricts itself to its configured domains, but libvirt access is
  effectively host-root equivalent. It is not a separately confined
  privileged service.
* Guest-to-relay traffic is plain HTTP on the isolated bridge, authenticated
  by HMAC, not encrypted. The relay uses verified TLS to a remote builder.
* Integrity is not authenticity (see Protocols and trust).
* The demonstration was interactive (keyboard through libvirt, screenshots as
  evidence) plus the agent's and builder's journals. It is not a gated
  harness run.
* One host test run (of about 26) ended with an error that was not reproduced
  in 22 repetitions.

## Reproduction

```bash
W=.work/merlin-20261121
# 9A: native build, lab suite (UP, MP, TCG)
python3 build/prepare_merlin.py --output $W/native-media-08
python3 vm/merlin_native_build.py --media $W/native-media-08 --name merlin-native-08 \
  --base $W/reference/build-vm-ai/disk.qcow2 --guest-modules $W/guest-modules-82/WINDOWS/system32 \
  --toolchain .work/toolchains/mingw-binutils/usr/bin
python3 vm/merlin_lab.py launch --name <fresh> --mode up|mp|tcg --image m9 --build $W/native-08-lab
python3 vm/merlin_lab.py wait <fresh> && python3 vm/merlin_lab.py results <fresh>
# 9B: builder VM, installation and agent registration
B=.work/merlin-builder-vm-20261121/vm-01
python3 components/merlin/builder/deploy/builder_vm.py provision --dir $B \
  --cloud-image .work/merlin-builder-vm-20261121/download/noble-server-cloudimg-amd64.img \
  --baseline-image $W/merlin-image-01/XP25-M9-MerlinAI.qcow2 --buildvm-image $W/reference/build-vm-ai/disk.qcow2
python3 components/merlin/builder/deploy/builder_vm.py bootstrap --dir $B --repo . --commit <approved> \
  --baseline-image-sha256 0f04a4381c6aedd6956a3b5d0a09e2e539947395ef94ef0f52598beca9314d32 \
  --revision XP25-M9-MerlinAI-1 --toolchain .work/toolchains/mingw-binutils --reference .work/merlin-builder-vm-20261121/reference
python3 components/merlin/builder/deploy/builder_vm.py register --dir $B --installation xp25-merlin-demo
python3 components/merlin/builder/deploy/builder_vm.py register --dir $B --agent xp25-host --installations xp25-merlin-demo
# 9D: demonstration VM, host services, enrollment
python3 components/merlin/host/enroll_vm.py create --dir .work/merlin-demo-vm-20261121 --image $W/merlin-image-01/XP25-M9-MerlinAI.qcow2
python3 components/merlin/host/enroll_vm.py enroll --dir .work/merlin-demo-vm-20261121 --installation xp25-merlin-demo \
  --builder-key <key> --agent-config .work/merlin-demo-vm-20261121/host/agent.json
systemctl --user enable --now merlin-relay merlin-deploy-agent      # units in components/merlin/host
python3 components/merlin/host/merlin_deploy_agent.py --config <agent.json> restore-current xp25-merlin-demo   # operator recovery
# an existing virt-manager VM (XP25-Winlogon-Fix): shut off, disk replaced by the tested image, filter + domain redefined
virsh -c qemu:///system nwfilter-define components/merlin/host/xp25-browser-merlin.nwfilter.xml
python3 components/merlin/builder/deploy/builder_vm.py add-baseline --dir $B --name xp25wf4 --repo . --commit 361a3b6d0 \
  --image .work/merlin-vm-20261122/image-04/XP25-Winlogon-Fix-MerlinAI.qcow2 --revision XP25-Winlogon-Fix-MerlinAI-1 --symbols <linker maps>
# (snapshot commit cf8bdf54, disk serial merlin-bl-xp25wf4)
python3 components/merlin/builder/deploy/builder_vm.py register --dir $B --installation xp25-winlogon-fix --baseline xp25wf4
python3 components/merlin/builder/deploy/builder_vm.py register --dir $B --agent xp25-host-wf --installations xp25-winlogon-fix
python3 components/merlin/host/enroll_vm.py enroll --dir <dir with vm.json> --installation xp25-winlogon-fix \
  --builder-key-file $B/keys/xp25-winlogon-fix.json --agent-config <agent.json> --disk-dir <VM directory> \
  --builder-agent xp25-host-wf --builder-agent-key-file <file> [--keyboard]
systemctl --user restart merlin-deploy-agent      # then log on once (offline enrollment) and wait for the health report
python3 components/merlin/host/merlin_deploy_agent.py --config <agent.json> adopt xp25-winlogon-fix XP25-Winlogon-Fix-MerlinAI-1
```
