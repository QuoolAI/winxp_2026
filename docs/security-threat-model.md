# XP25 security threat model (Milestone 8)

This is the threat model the Milestone 8 security baseline was built against. It
describes the system as it was inspected and tested in recorded guests
([inventory](security-baseline.md), [test record](security-regression.md)), not
as Windows XP is generally described. Statements about behavior cite a recorded
run; everything else is marked as an assessment.

XP25 does **not** have the security properties of a current Windows release.
The baseline reduces what is reachable and closes specific holes; it does not
make an NT 5.1 system safe for hostile networks or untrusted code.

## System under consideration

| Part | What it is here |
| --- | --- |
| Kernel, HAL, Win32k, CSRSS, ntdll, Kernel32, User32, GDI32, LSA server, SCM, Session Manager and 13 more | Built by this project from the NT 5.1.2600.**1106** (Service Pack 1 era) source, checked builds (25 binaries, see the inventory) |
| Everything else in `system32` | The installed, patched Service Pack 3 binaries (883 SP3-level files), Internet Explorer 8 and Windows Script Host 5.7 |
| Logon process | XP25's own Winlogon (`components/winlogon`, build 10) hosting the original MSGINA |
| XP25 components | ClippyAI, RoverAI, `xp25agent.dll` and the `XP25Broker` service (LocalSystem) in `C:\Program Files\XP25` |
| Accounts | `XP25` (administrator, blank password, the daily account), `Administrator` (enabled), `Guest`/`HelpAssistant`/`SUPPORT_388945a0` (disabled) |
| Network | One RTL8139 adapter. In every lab run it is attached to a Linux network namespace without an uplink |

Two properties dominate everything below:

1. **The daily account is an administrator.** NT 5.1 has no UAC, integrity
   levels or UIPI. Any program the `XP25` user runs has full control of the
   system. The baseline cannot change that without changing how the system is
   used; it narrows what such a program can reach *from outside* and what a
   *restricted* or *ordinary* process can do.
2. **The source-built core predates Service Pack 2.** The 25 project-built
   binaries carry none of the fixes Microsoft made to those components after
   2003, are not compiled with `/GS` and have no SafeSEH tables. Kernel-level
   mitigations (DEP, ASLR, driver signing) do not exist. See
   [kernel-level limitations](security-baseline.md#kernel-level-security-limitations).

## Assets

- The administrator boundary: `SYSTEM`, the kernel, files in `%SystemRoot%`,
  `HKLM`, service configuration.
- Credentials: the SAM and LSA secrets, the Winlogon/MSGINA password dialogs,
  secrets ClippyAI stores through Credential Manager.
- The integrity of the security configuration itself (firewall, disabled
  services, audit policy, the baseline's own backup and reference snapshot).
- The host and the host's LAN.

## Trust boundaries

| Boundary | Enforced by | Where |
| --- | --- | --- |
| Guest ↔ Internet, host LAN, other VMs | Linux network namespace with no route out (`vm/isolated_network.py`); for the browser, the allowlist gateway of Milestone 7B | **Host** |
| Guest disk ↔ verified images | Read-only backing files, disposable qcow2 overlays | **Host** |
| Network ↔ guest listeners | Windows Firewall (`ipnat.sys` + SharedAccess), disabled services | Guest |
| Ordinary user ↔ administrator/SYSTEM | Access tokens and security descriptors on files, keys, services, processes | Guest |
| Restricted process of an administrator ↔ the same administrator | Deny-only Administrators SID, removed privileges, Job Object; object *ownership* (see threat 2) | Guest |
| User desktop ↔ logon desktop | Winlogon desktop ACL and USER's logon-desktop check | Guest |
| ClippyAI (user) ↔ XP25Broker (SYSTEM) | Named-pipe impersonation, fail-closed service policy | Guest |

The host-enforced rows hold whatever happens inside the guest: a fully
compromised guest still has no route to the Internet or the LAN. The
guest-enforced rows are what Milestone 8 audits and hardens.

## Threats

Severity is this project's assessment for *this* system. "Before" is the
verified combined base (AI image-05 plus the XP25 Winlogon) as recorded in runs
`audit-up-01` and `audit-kx-up-01`; "after" is the hardened configuration.

### 1. Malicious application running as an ordinary user

An ordinary (non-administrator) account must not be able to change the system.

- **Before:** one real hole. `C:\WINDOWS\system32\ue51sp3.dll`, the Service
  Pack 3 UserEnv companion that the project's `userenv.dll` forwards to, had
  been copied in offline and carried an ACL granting **Everyone full control**.
  It is loaded into Winlogon and services, so an ordinary user could run code
  as SYSTEM by replacing it. Everything else that was probed (65 cases) was
  denied.
- **After:** closed; the file inherits `system32`'s ACL. On the hardened image
  the same account is refused in all 71 probed cases (system files, kernel,
  hives, `HKLM` run and policy keys, service configuration, privileged
  processes, the logon desktop, the baseline's store, asking the SYSTEM broker
  to stop the firewall).
- **Remaining:** an ordinary user can still create directories in `C:\` and
  write their own `HKCU` autostart entries (NT 5.1 design; reported by the
  audit, not changed), and is exposed to every local kernel vulnerability of an
  unpatched 2003-era kernel (threat 2).

### 2. Privilege escalation

- **Kernel and Win32k.** The source-built kernel and `win32k.sys` have no
  post-2003 fixes. Public local escalation techniques for NT 5.1 from that
  period must be assumed to work. *Not mitigated; not tested.* This is the
  largest remaining risk for any scenario with an untrusted local user.
- **Restricted process of the administrator.** Milestone 7B contains the
  browser with a restricted token of the logged-on administrator. NT gives the
  *owner* of an object the right to rewrite its ACL, and on NT 5.1 an
  administrator's files and keys are owned by the account, not by the
  Administrators group. **Before**, such a process could overwrite the kernel
  image, the HAL, the NTFS driver, `XP25Broker.exe` (SYSTEM service), the
  RoverAI COM registrations Explorer loads, and the broker's policy key
  (12 failed probe cases). **After**, those objects are owned by
  Administrators and new objects created by an administrator are too
  (`nodefaultadminowner=0`); all 73 restricted-token cases are refused.
  **Remaining:** other files and keys the administrator created before the
  baseline, outside the locations it manages (for example other programs under
  `Program Files`), keep their owner. A containment that must hold against a
  determined attacker should run under a separate ordinary account.
- **Services.** No service's configuration is writable by ordinary users
  (audit of all 84 services and 1,156 service keys). `XP25Broker`, however,
  stopped the Windows Firewall for any interactive user (`SharedAccess` was on
  its default allowlist): in run `audit-kx-up-02` an ordinary account did so
  and the open ports were reachable again. The policy now refuses the firewall
  and the Security Center unconditionally and no longer offers network-facing
  services (AI build 11, installed in the hardened image; probed).
- **Power Users.** Power Users can modify `Program Files`, `HKLM\Software` and
  service files on NT 5.1, which is enough to become an administrator. Nobody
  is a member; the audit reports membership.

### 3. Browser compromise

Internet Explorer 8/MSHTML is installed and is part of Explorer, HTML Help and
any program that embeds it. It cannot be removed without breaking them.

- **After:** Internet-zone content cannot run script, ActiveX, Java or binary
  behaviors, and zones are taken from machine settings only, so a user-level
  program cannot lower them. Local, intranet and trusted zones are unchanged.
- **Remaining:** MSHTML still parses Internet-zone HTML, images and fonts with
  2014-era code; TLS is limited to what Schannel on NT 5.1 offers (TLS 1.0).
  Supermium (Milestone 7) stays experimental and has no renderer sandbox on
  NT 5.1. Browsing untrusted sites is **not** made safe by this milestone; the
  host-side gateway and allowlist remain the control that matters.

### 4. Malicious documents and files

- Script files (`.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`) open in Notepad when
  double-clicked instead of running; `cscript`/`wscript` still run them when
  named explicitly.
- Compiled HTML Help shows local content only (`MaxAllowedZone=0`).
- AutoRun is off for removable, fixed, network and RAM drives; optical media
  keep it for game and software discs (a deliberate compatibility decision).
- **Remaining:** `.hta`, `.chm` opened locally, WinHelp macros, shell scrap
  objects, the `hcp:` protocol, and every document parser on the system run
  with the user's — here an administrator's — rights.

### 5. Vulnerable Windows services reachable from the network

- **Before (`audit-up-01`):** TCP 135 (RPC endpoint mapper) and 139 (NetBIOS
  session) answered from the network, UDP 123 and 137 answered, ICMP echo was
  answered, and **Windows Firewall was not running**: its driver `ipnat.sys`
  imports `KeFlushQueuedDpcs`, which the project's kernel did not export. IKE
  listened on UDP 500/4500 inside LSASS.
- **Firewall alone was not enough.** With the firewall running, the NetBIOS
  name service on UDP 137 still answered a neighbour 60 times out of 60 while
  the guest was broadcasting name queries (`audit-kx-up-04`): Windows Firewall
  admits unicast packets for three seconds after each broadcast the computer
  sends. That is also the path for answering the computer's name queries
  falsely.
- **After:** the kernel exports the routine (Microsoft's own, already in the
  source), the firewall runs and refuses replies to the computer's own
  broadcasts, and a scan of 1,113 TCP ports, 8 UDP services and 60 repeated
  name-service probes from the adjacent network, made while the guest
  broadcasts, finds nothing open and no reply to ICMP echo. Remote
  Registry, WebDAV, IPSEC Services, Automatic Updates and Error Reporting are
  disabled and stopped; Server, Computer Browser, SSDP, UPnP host, Remote
  Assistance and NetMeeting sharing are disabled.
- **Remaining:** RPC (135) and NetBT (137–139, 445) are still *bound* and are
  reachable from the local machine, and from the network again if the firewall
  is switched off by an administrator. The Server service cannot start at all
  on this kernel (see the inventory), which is an accident of the build, not a
  control.

### 6. Malicious device drivers

Only administrators hold `SeLoadDriverPrivilege` (audited). There is **no
driver signature enforcement** on NT 5.1 and none was added: an administrator,
or anything running as one, can load any driver. The audit lists driver
services and loaded kernel modules and reports additions against its reference
snapshot. *Detection only.*

### 7. Unauthorized modification of system files

- Ordinary and restricted processes are denied (threats 1 and 2).
- **Windows File Protection is not active.** WFP is hosted by the original
  Winlogon; the XP25 Winlogon does not host it. Even where it runs (image-05
  has the original Winlogon) it would treat the 25 source-built files as
  corrupt: `sfc /scannow` would be expected to restore Service Pack 3 files
  over the project's kernel-matched ones. Do not run it. *Assessment from the
  file inventory; not executed.*
- An administrator can replace any system file. The audit's reference snapshot
  does not hash system files (a recommended next step).

### 8. Persistence

The audit reads 28 registry autostart locations, the Startup folders, scheduled
tasks, services and drivers, compares single-valued settings (Shell, Userinit,
AppInit_DLLs, LSA packages, …) with their installed defaults, and reports
anything added or changed since the reference snapshot. In the recorded drift
test it reported an added `Run` value and a re-enabled service. *Detection
only; nothing is blocked or removed.* Per-user persistence (`HKCU\...\Run`) is
possible by design.

### 9. Credential theft

- LM hashes are no longer stored at the next password change (`nolmhash=1`);
  the client sends NTLMv2 only; anonymous enumeration is restricted; blank
  passwords work at the console only.
- LSASS memory cannot be opened by ordinary or restricted processes (probed).
- The logon desktop cannot be opened from the user session, even by an
  administrator (probed on the XP25 Winlogon).
- **Remaining:** the daily account has a **blank password**; an administrator
  can read LSASS; `wdigest` keeps plaintext credentials in LSASS memory on
  NT 5.1; cached credentials and LSA secrets are protected by 2001-era
  cryptography.

### 10. Guest-to-host and guest-to-LAN exposure

Enforced on the host: the guest's adapter is a tap device in a network
namespace that has no default route, no forwarding and no uplink (recorded per
run in `network-isolation.json`). QEMU runs as an ordinary host user. This
milestone did not change or weaken that arrangement, did not touch the
`XP25-AI` virtual machine, and did not test QEMU escape.

## Cryptography

| Area | State on XP25 | Note |
| --- | --- | --- |
| Providers | Microsoft Base/Enhanced/Strong RSA, DSS/DH, RSA+AES "(Prototype)", Schannel providers | `rsaenh.dll` 5.1.2600.5507 |
| TLS | Schannel on NT 5.1: SSL 2.0/3.0 and TLS 1.0, no TLS 1.1/1.2, SHA-1 era cipher suites | Protocol keys exist but are unconfigured; not changed in this milestone |
| Certificates | CryptoAPI chain building with the root store as installed | No updated root list; SHA-2 support as in `crypt32.dll` 5.131.2600.6459 |
| Random numbers | `CryptGenRandom` (`rsaenh`), the kernel's `ksecdd` | Used by the probe; not evaluated |
| Password storage | NT hashes in the SAM under SYSKEY (boot key exchanged by the XP25 Winlogon); LM hashes until the next password change | `nolmhash=1` set by the baseline |
| Network authentication | NTLMv2 responses only as client (`lmcompatibilitylevel=3`); the server side still accepts LM/NTLM | The Server service is disabled |
| Pointer encoding | `EncodePointer` uses a per-process kernel cookie added by this project | Obfuscation, not a cryptographic facility |

No cryptographic component was replaced. Modern TLS for applications has to
come from the application (Supermium carries its own).

## What this milestone does not claim

- No equivalence with Windows 10/11 security.
- No kernel memory protections, no ASLR, no DEP, no driver signing.
- No protection against a program run by the administrator account.
- No assurance about vulnerabilities that were not tested; passing tests show
  that specific operations are refused, not that the system has no flaws.
