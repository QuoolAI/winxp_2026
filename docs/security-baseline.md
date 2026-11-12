# XP25 security baseline (Milestone 8)

Work on branch `xp25-security` (worktree `xp25-security`), based on `xp25-nt` at
`d0db1f036`. Private evidence is under `.work/security-20261111/` (`W`) of this
worktree; build-VM runs are under `.work/boot-debug-20261022/` (`B`).

This document is the audit inventory and the description of what the baseline
changes. The [threat model](security-threat-model.md) explains why, the
[regression record](security-regression.md) has the commands, hashes and
results, and the [interface](security-engine-interface.md) describes the tools.

## Result

`XP25-Security-Baseline.qcow2` (SHA-256
`6da7d04ed4f2f768d390be875228643648a7a36801e4bfe37854fdf8d7ee45d9`, standalone) is
the verified AI image plus the XP25 Winlogon, a kernel whose export list gains
one routine, the rebuilt AI binaries, the two security tools and the applied
baseline. On fresh overlays of it, under one-vCPU KVM, two-vCPU KVM and TCG,
nothing answers from the adjacent network, an ordinary account and a restricted
token are refused every probed modification, the audit reports no
high-severity finding, and the AI and compatibility suites pass
([record](security-regression.md)). The largest remaining risks are listed as
findings 6, 7, 23 and 24 below: an unpatched 2003-era kernel and core, an
administrator as the daily account, no driver signing and TLS 1.0.

## Starting point

The milestone starts from two previously verified lines that had never been
combined: the AI image (`XP25-AI-Engineering.qcow2`, image-05, SHA-256
`ec22f45b…be2a`, original Winlogon) and the natively built XP25 Winlogon
(build 10, `e3a9cdca…df93`, verified on its own engineering image). The hardened
image keeps both. Before any hardening the combination was booted and passed the
complete established suite (run `pre-up-02`: AI 55/0 and 7/0, every
compatibility probe 0, MSI install and removal, XP25 Winlogon logon with
`licdll` admission, shutdown from the desktop).

Frozen inputs are reflink copies under `W/reference/` with their hashes in
`W/reference/manifest.json`. The originals and every other image, including the
`XP25-AI` virtual machine and its overlay, were not opened for writing.

## What is installed (offline inventory)

`vm/security_offline_audit.py` reads the frozen image without booting it
(`W/offline-audit-03/inventory.json`).

| Group | Count | Notes |
| --- | --- | --- |
| PE binaries inspected (`WINDOWS`, `system32`, `drivers`, `wbem`, XP25 and bundled program directories) | 1,977 | |
| Built by this project from the 5.1.2600.1106 source | 25 | All checked (debug) builds, linker 7.0, **no `/GS` cookie, no SafeSEH** |
| Service Pack 3 level system files | 883 | 647 with `/GS` |
| RTM-level files (never updated) | 416 | None with `/GS` |
| Binaries with `NXCOMPAT` / `DYNAMICBASE` set | 118 / 121 | Later components only; NT 5.1 honours neither |

The 25 source-built binaries: `xp25krnl.exe`, `xp25hal.dll`, `win32k.sys`,
`csrss.exe`, `csrsrv.dll`, `basesrv.dll`, `winsrv.dll`, `ntdll.dll`,
`kernel32.dll`, `user32.dll`, `gdi32.dll`, `imm32.dll`, `lsasrv.dll`,
`secur32.dll`, `services.exe`, `smss.exe`, `msgina.dll`, `userenv.dll`,
`regsvc.dll`, `ws2_32.dll`, `ws2help.dll`, `wshtcpip.dll`, `framebuf.dll`,
`mountmgr.sys`, `xp25ntfs.sys`. `explorer.exe` (6.0.2800.1106) is also a
project build. The original Service Pack 3 `ntoskrnl.exe`, `hal.dll` and
`ntfs.sys` are still on disk but are not what boots.

Other installed components relevant to the audit: Internet Explorer
8.0.6001.18702 with `mshtml.dll` 8.0.6001.23536, Windows Script Host 5.7,
HTML Help 5.2.3790.2453, `tcpip.sys` 5.1.2600.6009, `srv.sys` 5.1.2600.6082,
`rpcss.dll` 5.1.2600.5755, `crypt32.dll` 5.131.2600.6459.

## Vulnerability and attack-surface inventory

Severity and exploitability are this project's assessment. "Observed" means a
recorded guest run showed it; "static" means it follows from the file or
registry inventory and was not exercised.

| # | Finding | Severity | Exploitability | Evidence | Remediation in this milestone | Compatibility impact |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | **Windows Firewall cannot start**: `ipnat.sys` imports `KeFlushQueuedDpcs`, not exported by the project kernel. TCP 135 and 139 open, UDP 123 and 137 answering, ICMP echo answered | High | Remote, unauthenticated reach to RPC and NetBT | Observed (`audit-up-01` scan; System log 7023 `%%127`; `W/import-check-01`) | **Fixed.** The kernel's export list gains the routine (already in the source); firewall enabled for both profiles | None observed |
| 1a | With the firewall running, **UDP 137 still answers** neighbours: Windows Firewall admits unicast packets for three seconds after each broadcast the computer sends, and NetBIOS broadcasts keep that open | Medium | On-link host reaches the NetBT name service and can answer name queries falsely (credential capture by name spoofing) | Observed (`audit-kx-up-04`: 60 of 60 probes answered while the guest broadcast; first seen under TCG in `harden-tcg-01`) | **Fixed.** Unicast responses to the computer's own broadcasts are refused | No NetBIOS broadcast name resolution; LAN discovery by broadcast needs the program's firewall exception. DHCP unaffected |
| 2 | `system32\ue51sp3.dll` writable by **Everyone** (copied in offline without an ACL); loaded by Winlogon and services | High | Any local account → SYSTEM | Observed (ordinary-account probe) | **Fixed.** Reset to the directory's ACL | None |
| 3 | Kernel image, HAL, NTFS driver, `XP25Broker.exe` and the XP25 program directory **owned by the administrator account**; a restricted process of that account can rewrite them | High for the browser containment | Restricted token of the logged-on administrator → SYSTEM | Observed (12 restricted-token cases) | **Fixed.** Ownership and ACLs repaired; new objects owned by Administrators (`nodefaultadminowner=0`) | Programs that compare a file's owner with the user see the Administrators group |
| 4 | `HKLM\SOFTWARE\XP25` (broker policy), RoverAI COM registrations and 16 CLSID keys modifiable without administrator rights (3 by Everyone) | High | Same as 3; COM hijack into Explorer | Observed (audit scan of 13,534 CLSID keys) | **Fixed.** Keys reset to inherited ACLs; `SOFTWARE\XP25` protected | None |
| 5 | `XP25Broker` (SYSTEM) stops the Windows Firewall for any interactive user: `SharedAccess` was on its default allowlist | High once the firewall runs | An ordinary or restricted account switches the firewall off | Observed (`audit-kx-up-02`: an ordinary account stopped it and TCP 135/139 were reachable again) | **Fixed**: the policy refuses the firewall and the Security Center unconditionally and no longer offers network-facing services; AI build 11 is installed in the image | ClippyAI no longer offers to restart those services |
| 6 | Source-built kernel, Win32k and core DLLs carry no post-2003 fixes; no `/GS`, SafeSEH, DEP or ASLR | High | Local escalation with public NT 5.1 techniques must be assumed | Static | **Not addressed.** Future kernel-hardening milestones | — |
| 7 | Daily account `XP25` is an administrator with a blank password; `Administrator` enabled | High | Anything the user runs is an administrator | Observed (audit accounts) | Not changed (would alter how the VMs are used). Blank passwords stay console-only; audit reports it | — |
| 8 | Remote Registry running (auto) | Medium | Remote administration over `winreg` if SMB were reachable | Observed | **Disabled** | Remote registry editing needs an administrator to re-enable it |
| 9 | IKE (UDP 500/4500) inside LSASS | Medium | Unauthenticated datagrams parsed in the credential process | Observed (listener table) | **IPSEC Services disabled**; ports no longer bound | No IPsec policies or L2TP/IPsec until re-enabled |
| 10 | WebDAV redirector running | Medium | UNC paths reach arbitrary HTTP servers and forward credentials | Observed | **Disabled** | WebDAV servers cannot be mapped as drives |
| 11 | Automatic Updates and Error Reporting running against retired endpoints | Medium | Spoofable update channel; crash data upload | Observed | **Disabled** | No Windows Update; plain crash dialog |
| 12 | Server (SMBv1), Computer Browser, SSDP, UPnP host, Remote Assistance, NetMeeting sharing startable | Medium | SMBv1 server and discovery listeners once started | Observed (start types). Server and HTTP-dependent services currently cannot start on this kernel at all (missing `RtlIpv4AddressToStringExW`, push-lock exports) | **Disabled**, so a later kernel fix does not silently expose them | This computer shares nothing and announces nothing |
| 13 | No security auditing; Security log 512 KiB, no overwrite | Medium | Activity leaves no record | Observed | **Audit policy enabled** (logon, account logon, account management, policy change, system: success and failure; privilege use: failure); Security log 16 MiB, overwrite as needed | Up to 16 MiB of disk |
| 14 | Internet-zone script and ActiveX in MSHTML; zones changeable per user | Medium | Browser/document compromise through unmaintained engine | Static (registry) | **Internet zone locked** (script, ActiveX, Java, behaviors off) and machine-only zones | Internet-zone pages lose active content in IE and embedded browsers |
| 15 | Script files run on double-click | Medium | Mail/download → code execution | Static (file associations) | **Default verb is Edit** for `.vbs .vbe .js .jse .wsf` | `cscript`/`wscript` unaffected |
| 16 | AutoRun enabled for removable and network drives (`0x91` default) | Medium | USB or share → code execution | Static | **`NoDriveTypeAutoRun=0xDF`**: only optical media keep AutoRun | Game and software discs still start setup |
| 17 | LM hashes stored; anonymous enumeration allowed; null-session pipes and shares listed; Remote Assistance allowed | Medium/Low | Credential cracking; information disclosure if SMB is reachable | Static | **Set**: `nolmhash=1`, `restrictanonymous=1`, empty null-session lists, `fAllowToGetHelp=0`, SMB signing where supported | Windows 9x-era peers |
| 18 | Source routing, ICMP redirects and router discovery accepted; NetBIOS name release honoured | Low | On-link traffic redirection | Static | **Set** to the hardened values | None with DHCP or static configuration |
| 19 | `C:\xp25` (Winlogon log, lab tools) writable by Users and owned by the administrator account | Medium | Planting files a SYSTEM process or the administrator opens | Observed (60 of 62 objects) | **Fixed.** Protected ACL | Only administrators write there |
| 20 | Windows File Protection not hosted by the XP25 Winlogon; `sfc /scannow` would revert source-built files | Medium | Self-inflicted outage; no automatic repair of system files | Static | Documented; not changed | — |
| 21 | `shutdown.exe` and `InitiateSystemShutdown` fail under the XP25 Winlogon (`InitShutdown` RPC interface not served) | Compatibility defect, and one remote interface fewer | — | Observed (`pre-up-02`: "The network path was not found") | Not changed; recorded in COMPATIBILITY.md | Installers that reboot through this API cannot reboot |
| 22 | Users may create directories in `C:\`; every authenticated user may create scheduled tasks; per-user autostart | Low | Planting for unquoted paths; persistence as oneself | Observed (probe, audit) | Not changed (NT 5.1 design); audit reports it | — |
| 23 | No driver signature enforcement | High for an administrator-level attacker | Any administrator loads kernel code | Static | Not addressed; audit lists drivers and reports new ones | — |
| 24 | TLS 1.0 only in Schannel; SHA-1 era trust | Medium | Network attacker against system TLS clients | Static | Not addressed | — |
| 25 | `.hta`, local `.chm`, WinHelp macros, scrap objects, `hcp:` protocol | Medium | Document → code as the user | Static | Not changed (`MaxAllowedZone=0` set for remote CHM) | — |

## What the baseline changes

`XP25Sec.exe apply` records every original value first and applies only the
tables in `components/security/core/sec_core.c`. On the combined base it
changed 62 items and found 19 already compliant, with no failure (run
`harden-up-04`); `verify` then checks 90 items (18 services, 54 settings, 9
audit categories, 8 access-control rules and the protected store).

### Services (18 rules)

| Service | Before | After | Why |
| --- | --- | --- | --- |
| `RemoteRegistry` | auto, running | disabled | Remote administration |
| `PolicyAgent` (IPSEC Services) | auto, running | disabled | IKE listener in LSASS |
| `WebClient` | auto, running | disabled | WebDAV redirector |
| `wuauserv`, `ERSvc` | auto, running | disabled | Retired vendor endpoints |
| `LanmanServer`, `Browser` | auto, not running | disabled | SMBv1 server, NetBIOS browsing |
| `SSDPSRV`, `upnphost` | manual | disabled | Discovery listeners |
| `RDSessMgr`, `mnmsrvc` | manual | disabled | Remote Assistance, NetMeeting desktop sharing |
| `Messenger`, `Alerter`, `NetDDE`, `NetDDEdsdm`, `ClipSrv`, `TlntSvr`, `RemoteAccess` | disabled | disabled (enforced) | Legacy remote protocols |

Result on the single-vCPU run: 39 → 34 running Win32 services, 35 → 28
automatic, 8 → 19 disabled. A table in the same source file lists 42 services
the baseline may never touch (RPC, DCOM, Plug and Play, Event Log, SAM, the
firewall, Secondary Logon, Themes, Spooler, Workstation, Task Scheduler,
`XP25Broker`, …); a host test fails if a rule ever names one, and `apply`
refuses to run.

Not disabled, deliberately: Workstation (SMB client; needed for existing
networking), Spooler (applications fail without it), Terminal Services (Fast
User Switching; inbound Remote Desktop stays refused by `fDenyTSConnections`),
Task Scheduler, Help and Support, W32Time.

### Registry settings (54 rules)

| Area | Settings |
| --- | --- |
| LSA | `restrictanonymous≥1`, `restrictanonymoussam=1`, `everyoneincludesanonymous=0`, `nolmhash=1`, `lmcompatibilitylevel≥3`, `limitblankpassworduse=1`, `nodefaultadminowner=0` |
| SMB | Server: `AutoShareWks=0`, `RestrictNullSessAccess=1`, empty `NullSessionPipes`/`NullSessionShares`, signing enabled. Client: signing enabled, no plaintext passwords |
| TCP/IP | `DisableIPSourceRouting=2`, `EnableICMPRedirect=0`, `PerformRouterDiscovery=0`, NetBT `NoNameReleaseOnDemand=1` |
| Remote access | `fDenyTSConnections=1`, `fAllowToGetHelp=0`, RPC `RestrictRemoteClients≥1` |
| Firewall | `EnableFirewall=1` and `DisableUnicastResponsesToMulticastBroadcast=1` for the standard and domain profiles; File and Printer Sharing, Remote Desktop, UPnP and remote administration exceptions off |
| AutoRun | `NoDriveTypeAutoRun=0xDF`, `HonorAutorunSetting=1` |
| Process | `SafeDllSearchMode=1`, `ProtectionMode=1` |
| Auditing | Security log `MaxSize≥16 MiB`, `Retention=0` |
| Help | `MaxAllowedZone=0` |
| Internet Explorer | `Security_HKLM_only=1`; Internet zone: download signed/unsigned ActiveX, run ActiveX, script unsafe ActiveX, active scripting, script safe ActiveX, binary behaviors disabled; Java off |
| Windows Script Host | Default verb `Edit` for `VBSFile`, `VBEFile`, `JSFile`, `JSEFile`, `WSFFile` |

Settings where a higher value is stricter are raised, never lowered. Keys the
tool creates are owned by the Administrators group from the start.

### Audit policy

Success and failure for system, logon, account logon, account management and
policy change events; failure for privilege use. Object access and process
tracking stay off: without SACLs and with every process start logged they
would bury the useful records.

### Access control (8 rules)

| Rule | Scope | Action |
| --- | --- | --- |
| `acl.windows`, `acl.system32`, `acl.drivers` | Every file directly in the three directories | Files an unprivileged group, an individual account or a non-system owner can modify are reset to the directory's inherited ACL, owned by Administrators (5 files on the combined base) |
| `acl.xp25_programs` | `C:\Program Files\XP25` | Protected ACL: SYSTEM and Administrators full, Users read and execute |
| `acl.xp25_lab` | `C:\xp25` | Same |
| `acl.xp25_registry` | `HKLM\SOFTWARE\XP25` | SYSTEM and Administrators full, Users read |
| `acl.service_keys` | Every key below `HKLM\SYSTEM\CurrentControlSet\Services` | Exposed keys reset to inherited ACLs |
| `acl.com_classes` | Every key below `HKLM\SOFTWARE\Classes\CLSID` | Same (16 keys) |

### Outside the tool

- **Kernel export.** `build/prepare_kernel_exports.py` adds one line,
  `KeFlushQueuedDpcs`, to `ntoskrnl.src` in the build VM's disposable source
  copy and relinks the kernels. The routine is Microsoft's, already compiled
  into the kernel (`base/ntos/ke/dpcobj.c`) and exported by Service Pack 2 and
  later; no kernel source file changes. The export tables of the new kernels
  differ from the previous ones by exactly that name (1,464 → 1,465).
- **XP25 broker policy.** `components/xp25-agent/permissions/xp25_policy.c`
  refuses `SharedAccess` and `wscsvc` unconditionally and offers only desktop
  services by default.

## Evaluated and deliberately not changed

| Area | Observation | Decision |
| --- | --- | --- |
| Software Restriction Policies | SAFER is present (`DefaultLevel` unrestricted, transparent enforcement on, used by Milestone 7B for the browser). A default-deny policy would stop installers, games and anything run from a profile | Not applied. Path rules for mail and browser caches are a candidate for a later milestone, after testing against game installers |
| Service accounts | 70 of 84 services are configured as LocalSystem (9 LocalService, 5 NetworkService), most of them in the shared `netsvcs` host, as installed. Moving services to LocalService/NetworkService changes what they can reach and is untested on NT 5.1 | Not changed. `XP25Broker` needs LocalSystem for service control; its attack surface is the policy check, which was tightened |
| User rights | Only Administrators hold debug, load-driver, take-ownership, security and remote-shutdown rights; backup and restore also go to Backup Operators (empty). "Access this computer from the network" still includes Everyone | Not changed: the Server service is disabled and the firewall filters inbound traffic. The audit reports sensitive rights held by broad groups |
| NetBIOS over TCP/IP, SMB client | NetBT stays bound (137–139, 445) and the Workstation service runs, for access to other computers' shares | Not changed. Inbound reachability is closed by the firewall rules above; the SMBv1 *client* remains |
| Spooler, Task Scheduler, Help and Support, Terminal Services | Local services with a history of vulnerabilities that many programs and the shell depend on | Not changed; none is reachable from the network |
| Internet Explorer and MSHTML | Part of Explorer, HTML Help and embedded browsers | Kept; Internet zone locked instead of removing the engine |
| Windows Script Host | The compatibility suite's MSI test and many installers use `cscript` | Kept; only the double-click action changed |
| Accounts | `XP25` administrator with blank password, `Administrator` enabled | Not changed (documented VM usage); reported by the audit |

## Original XP protections and new XP25 protections

| Protection | Origin | State |
| --- | --- | --- |
| NTFS and registry ACLs, tokens, privileges, service ACLs | NT 5.1 | Unchanged; verified by the probe |
| Windows Firewall | XP SP2 | **Restored** (was unable to start), enforced on, and no longer admitting replies to the computer's own broadcasts |
| RPC `RestrictRemoteClients`, blank-password console restriction, disabled Messenger/Alerter/NetDDE/Telnet | XP SP2 | Made explicit and enforced |
| Stack cookies and SafeSEH in Service Pack 3 binaries | XP SP2/SP3 | Present in SP3 files only; absent from the 25 source-built files |
| Logon desktop isolation | XP25 Winlogon | Verified: not openable from the user session |
| SAFER restricted token + Job Object around the browser | XP25 (Milestone 7B) | Ownership gap closed for system and XP25 objects |
| Disabled legacy services, hardened LSA/SMB/TCP settings, audit policy, IE zone lockdown, script and AutoRun handling | **New (XP25Sec)** | Applied, verified, reversible |
| Access-control repair of system files and XP25 objects, Administrators as default owner | **New (XP25Sec)** | Applied, verified |
| Read-only audit with reference snapshot | **New (XP25Audit)** | Installed; run on demand |
| Broker refuses to control the firewall | **New (xp25agent, AI build 11)** | Installed; probed from the ordinary account and the restricted token |

## Rollback

There are two levels, both tested ([record](security-regression.md)):

1. **Configuration.** `XP25Sec rollback` (administrator) restores every recorded
   original: service start types (and restarts services that were running),
   registry values (deleting values that did not exist), audit policy, and the
   recorded owner and ACL of each repaired object, then removes the baseline
   state. Restart afterwards. If the registry copy of the backup is lost,
   `XP25Sec rollback --from %SystemRoot%\XP25\Security\baseline-backup.txt`.
   Tested in run `rollback-up-02` on the image: 97 records restored, none
   failed; afterwards the service start types equalled the recorded ones, the
   five services that had been running ran again, `verify` reported 71
   deviations and the unchanged Remote Registry probe passed.
   Limits: keys the baseline created stay as empty keys; inside the three XP25
   trees only the root's original ACL is restored and children inherit from it
   (their previous individual owners are not restored); the kernel export and
   the rebuilt AI binaries are not part of the tool's rollback.
2. **Image.** The previous verified images are untouched and still boot. To go
   back completely, create a new overlay on `XP25-AI-Engineering.qcow2`
   (`ec22f45b…be2a`) or `XP25-Winlogon-Engineering.qcow2` (`0df7fc05…c51c`).

An administrator can also re-enable a single service (`sc config <name> start=
demand`); `XP25Sec verify` and the audit then report the deviation, and
`XP25Sec apply` restores the baseline.

## Kernel-level security limitations

- The running kernel, HAL and `win32k.sys` are checked builds of the
  5.1.2600.1106 source. They contain assertions and debug paths, and none of
  the kernel security fixes released after that tree.
- No hardware DEP (the kernel is not the PAE kernel and the lab CPU model has
  no NX), no ASLR, no kernel or user stack-cookie coverage in the source-built
  files, no SafeSEH tables in them.
- No driver signature enforcement and no PatchGuard-style integrity checks.
- Two installed Service Pack 3 drivers still cannot load on this kernel:
  `srv.sys` (needs `RtlIpv4AddressToStringExW`) and `http.sys` (push-lock,
  `KeFlushQueuedDpcs` and `RtlAddAccessAllowedAceEx` exports; the first of
  these is now exported, the others are not). The filter manager service is
  registered but its driver file is not on the disk. Their services are
  disabled or unused; exporting more routines is future work and each one
  needs its own review.
- Windows File Protection does not run under the XP25 Winlogon.

## Recommended next steps

1. Rebuild the source-built components with `/GS` and SafeSEH, and plan the
   kernel fixes that matter most for local escalation.
2. Give the daily account a password and move daily use to an ordinary account;
   run the browser under a dedicated ordinary account instead of a restricted
   token of the administrator.
3. Serve the `InitShutdown` interface locally in the XP25 Winlogon so
   `shutdown.exe` and installers can restart the system.
4. Extend the audit's reference snapshot with hashes of system files and wire
   `XP25Audit report` into ClippyAI as a read-only tool
   ([interface](security-engine-interface.md)).
5. Decide whether Windows File Protection should be hosted, with a catalog
   that knows the source-built files.
6. Signed XP25 updates, driver integrity and memory protections, as planned for
   later milestones.
