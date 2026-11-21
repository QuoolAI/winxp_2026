# Milestone 9: MerlinAI — self-repairing XP25 with a shared builder VM

Worktree `xp25-merlin` (branch `xp25-merlin`, from `xp25-modernization` `fa387ec3e`).
Evidence root `.work/merlin-20261121/` (`E`); native build-VM runs under
`.work/boot-debug-20261022/merlin-native-*`; builder VM under
`.work/merlin-builder-vm-20261121/`. `Source/` is not touched.

<!-- STATUS -->

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
`wuauserv` are SP3 binaries. MerlinAI hides the two applets with the
documented machine-wide "don't load" list, registers `MerlinAI.cpl` ("MerlinAI
Health and Updates", Security Center category) and turns off Security
Center's antivirus/firewall/update notifications. The Security Center
service, the Windows Firewall (SharedAccess, verified running) and auditing
are unchanged; Automatic Updates stays disabled as the 8.x baseline left it,
plus the `NoAutoUpdate` and `NoWindowsUpdate` policies.

Found on the way: the image's `shell32.dll` does not read the SP2 `Cpls` key
at all (the string is absent), and `control.ini [MMCPL]` is per user, so the
applet is installed in `system32`; the shell also drops `&` from applet names.
A guest probe (`tests/guest/merlin_probe.c`) enumerates the Control Panel
folder through `IShellFolder` and gates the replacement.

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
