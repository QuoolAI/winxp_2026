# XP25-AI remote access through Guacamole (2026-10-26)

**Result:** the rebuilt XP25-AI VM is reachable from a browser through the
existing Mise En Abyme (MEA) Guacamole deployment, by any verified Newbie user,
one at a time. A live end-to-end test signed in through the public site,
borrowed XP25-AI, used the mouse and keyboard in Windows, disconnected and
reconnected into the same session, and checked that a second user could not
take the seat until it was released. No home port forwarding, VPN or public
VNC/RDP/SSH/guacd port is involved, and the guest has no network adapter.

Operational scripts and instructions: [remote-access/README.md](../remote-access/README.md).

## 1. What the existing AWS deployment turned out to be

The task assumed Guacamole on an EC2 host with SSH. MEA instead runs Guacamole
1.6.0 and guacd in one ECS Fargate task behind an ALB. The ALB only forwards
Guacamole's token, tunnel and `guacamole-common-js` paths, so Guacamole's own
web UI is not public: users sign in to MEA, and MEA issues a single-use
Guacamole token. MEA's `mea-lifecycle` Guacamole extension refuses any tunnel
that is not tied to an MEA desktop lease. So the integration had to be an MEA
feature, not a Guacamole connection added by hand:

- **Shared desktops in MEA.** Borrowable machines with the normal lease rules
  and one seat. Built on the MEA release that was live at the time (pushed as
  `feature/m2-power-eleet-beta`), merged into branch
  `feature/xp25-ai-shared-desktop` in the Type3-hypervisor-manager and mea-web
  repositories, and deployed. Design, registration and deployment record:
  `mvp/docs/SHARED_DESKTOPS.md` in Type3-hypervisor-manager.
- **AWS tunnel end.** A Fargate task has no SSH server, so the tunnel ends on a
  small relay EC2 in the MEA VPC. guacd reaches the relay's private address, and
  the home host reaches the relay's loopback sshd through SSM Session Manager.
- **Release coordination.** The first look found another agent's unpushed MEA
  release live in production. Nothing was deployed until it was pushed. Rebuilds
  of the pushed commits then matched the live API binary and frontend bundle
  byte for byte, and no desktop session was connected at deploy time.

## 2. XP25-AI rebuilt

The VM was rebuilt from the accepted AI image-05
(`ec22f45b67af19f584eb6ca0a286e943731298543aa1b910eab6ff42674bee2a`, verified
before use and unchanged afterwards: hash, mode 0444, mtime and inode) with
the QuoolAI configuration from [xp25-vm-configuration.md](xp25-vm-configuration.md):
- a fresh overlay, `.work/virt-manager-XP25-AI-20261026/XP25-AI-Disposable.qcow2`;
- the previous overlay left untouched (SHA-256 `8a70205a…82a7`). It also holds
  changes made in the VM after the 2026-10-25 hand-off, which the rebuild does
  not carry over.

| Step | Result |
| --- | --- |
| Boot 1, `D:\vm-before.cmd XP25-AI` | Backups, observe-mode probe, HelpSvc values, rename; guest-requested shutdown |
| `vm_offline_update.py` (`sysdm.cpl` `98f3c968…`, `OEMINFO.INI` `7760193a…`) | `all_passed: true`; 5 AI binaries match image-05 |
| Boot 2, `D:\vm-verify.cmd`, then `vm_config_results.py` | 11/11 gates, `oem` probe all pass, name `XP25-AI`, activation data unchanged. The network gates do not apply: there is no NIC, and the ping exits are 1 as expected. |
| Hand-off boot | Luna desktop. The recurring Found New Hardware wizard for the VGA controller was finished with "Don't prompt me again". |

The command lines are the ones in xp25-vm-configuration.md, section 7, with
output directories under `.work/vm-rebuild-20261026/`, no `--ip`/`--peer-name`,
and `D:\vm-verify.cmd` given an unused peer address.

### Definition changes (`virsh define`, VM shut off)

| Setting | Before | After |
| --- | --- | --- |
| Disk | 2026-10-25 overlay | New overlay on image-05 |
| Network | RTL8139 on `XP25-Isolated` | **Removed.** The DHCP reservation in `XP25-Isolated` is left unused; the network itself is unchanged. |
| Console | VNC on loopback, autoport, no password | VNC on a fixed loopback port, with a VNC password (only in libvirt's secure XML and the MEA registration) |
| Pointer | PS/2 mouse | PS/2 mouse plus a USB tablet on a PIIX3 UHCI controller (was `usb model='none'`), so VNC pointing is absolute and the cursor matches the browser |
| COM1 | registration directory | `.work/virt-manager-XP25-AI-20261026/serial.log` |
| Autostart | disabled | **enabled** (only this domain), so the console returns after a host reboot; `libvirt-guests` handles host shutdown |

CPU, memory, machine type, VGA, ACPI and the CD-ROM (with the ISO the user
attached) are unchanged. `virt-xml-validate` accepted the definition.

## 3. The tunnel

| Part | Configuration |
| --- | --- |
| Relay EC2 | t4g.nano Amazon Linux 2023 in the MEA desktop subnet. IMDSv2 only (hop limit 1), encrypted root volume, no key pair, termination protection. Role with `AmazonSSMManagedInstanceCore` only. Daily security updates. Not tagged `MEAEnvironment`, so MEA's worker sweep cannot terminate it. |
| Relay security group | Inbound TCP 5900 only from the Guacamole task's group; outbound HTTPS only. No existing group or rule was changed. |
| Relay sshd | Listens on `127.0.0.1:22`. The only account, `xp25tunnel`, is a key-only `nologin` account with `AllowTcpForwarding remote`, `PermitListen <private address>:5900`, `PermitOpen none`, no TTY and `ClientAlive` 15 s × 3. |
| Home side | `xp25-tunnel.service`, run as the unprivileged `xp25-tunnel` system account. `ssh -N` with `ExitOnForwardFailure`, `ServerAlive` 30 s × 3, a pinned relay host key and a dedicated ed25519 key. `ProxyCommand` is `xp25-ssm-proxy`, which opens `AWS-StartSSHSession` as an IAM user limited to that instance and document. |
| Remote forward | relay private address:5900 → home `127.0.0.1` VNC port |

The first relay boot ran out of memory in `dnf` (512 MiB). The sshd part had
already been applied; the rest (swap, `dnf-automatic`) was completed over SSM
Run Command, and `relay-user-data.sh` now adds swap before `dnf`. This is
recorded in `.work/guacamole-remote-20261026/relay/`.

## 4. Verification

| Check | Result | Evidence |
| --- | --- | --- |
| VNC listens only on loopback | `127.0.0.1:<port>` only | `ss -ltn` |
| Tunnel from the home host, read through the relay | `RFB 003.008` from the relay's private address; relay sshd on `127.0.0.1:22` only | `relay/tunnel-tests-01.txt` |
| Tunnel key misuse | Command: "This account is currently not available."; TTY refused; other listen address refused; local forward (tried against the instance metadata service) "administratively prohibited" | same |
| Guacamole admin surface | `/guacamole/api/session/...` and `/guacamole/#/` return 404 from the public site | `e2e-02/.../report.json` |
| guacd in the Fargate task | guacd logs "Creating new client for protocol vnc" and users joining connection 11; Guacamole logs JSON-authenticated users connecting to and leaving "11" | CloudWatch `/mea/staging/guacd`, `/mea/staging/guacamole` |
| Browser end to end (`shared-e2e.mjs`, system Chromium 156) | **PASS**: offered on the dashboard; lease ready; Start menu opened by a mouse click; Notepad opened and text typed; disconnect and reconnect show the same Notepad and text; a second user sees "In Use", the button is disabled and the API returns 409; after "End session" the seat is free and the second user connects; both accounts deleted | `.work/guacamole-remote-20261026/e2e-02/` (browser and host screenshots) |
| First end-to-end run | Failed on two test mistakes: a case-sensitive "In use" check, and a first click that only woke the XP screen saver. It is kept with `failure.json`. | `e2e-01/` |
| MEA's own Ubuntu test (`live-e2e.mjs`), after the deploy | **Fails, identically with the previous frontend.** The XFCE desktop renders, but the frontend's paint check never leaves "Starting desktop", because the undrawn background is transparent. This is a pre-existing problem in the live release, recorded in `SHARED_DESKTOPS.md`. EC2 desktops were terminated by the watchdog. | `regression-01`, `-02-old-frontend`, `-03-ubuntu-diag` |
| Guest network | No NIC; ping exits 1 | `vm-rebuild-20261026/results/` |
| Frozen images, other VMs | image-05 unchanged. No other domain's definition or state was changed by this work (`XP25-Winlogon`, `xp25-sp3` and the other registered domains were shut off before it began). | `vm-rebuild-20261026/` |

Not observed:
- Windows shortcuts sent from the browser: Alt+F4 did not reach XP as a
  shortcut in the headless test. Letters, Enter and mouse input did.
- Clipboard transfer.
- Audio. It is disabled in MEA and the VM has none.

## 5. Security notes

- XP25 is treated as vulnerable. It has no network adapter, so it cannot reach
  the home LAN, the host's services, the internet, AWS credentials or the
  instance metadata service. Its only interface is the VNC console.
- Nothing listens publicly. The home host makes only outbound HTTPS
  connections, to AWS SSM. The relay accepts VNC only from the Guacamole task's
  security group, and SSH only on loopback through SSM.
- Sign-in is MEA's existing HTTPS sign-in with email verification. **MEA has no
  MFA**; adding it (for example TOTP for MEA accounts) is a required follow-up
  before treating this as more than a demo machine.
- Every verified Newbie user can control XP25-AI while holding the lease.
  Whatever one user leaves on screen, the next one sees. The guest's user
  account auto-logs on and has administrator rights. The residual host risk is
  a QEMU escape through the emulated devices: VGA, IDE, PS/2, a USB tablet and
  a CD-ROM.
- Leases follow MEA's limits: a 15-minute idle warning, 20-minute idle end, a
  5-minute disconnect grace and a 4-hour lifetime. Ending a lease does not
  reset the machine.

## Limits and open items

- The MEA Lambda packages were deployed with the AWS CLI. MEA's Terraform
  state (on the release machine) still records the previous package hash, so
  `feature/xp25-ai-shared-desktop` must be merged before the next MEA deploy.
- The tunnel IAM user has a long-lived access key, stored only in
  `/etc/xp25-tunnel` on the home host (mode 0600, owned by the tunnel account).
- 640×480 VGA without a display driver: XP shows its low-resolution balloon,
  and the browser scales the picture.
- ClippyAI has no model gateway on this VM; without a network it cannot reach one.

## Evidence

Under `.work/`:
- `vm-rebuild-20261026/`: definitions before and after, boot 1 and 2 screenshots, `offline/`, `results/`, `handoff/`.
- `guacamole-remote-20261026/relay/`: provisioning record (no secrets), tunnel tests.
- `guacamole-remote-20261026/deploy-01/`: commits, artifact hashes, the pre-deploy state, drain checks, migration result, rollback package.
- `guacamole-remote-20261026/e2e-01/` (failed run) and `e2e-02/` (passing run).
