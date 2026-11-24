# One XP25 VM, disposable Newbie desktops in Mise En Abyme, and the 2026-11-24 cleanup

On 2026-11-24 the host was reduced to one XP25 virt-manager VM, XP25-Winlogon-Fix. Mise En Abyme (MEA) changed
in two ways. Newbie users no longer share a VM: each connection now gets a fresh, disposable XP25 VM with Internet
access and MerlinAI. XP25-Winlogon-Fix is an administrator-only MEA desktop
([below](#the-admin-only-desktop)).

## Cleanup

* **Domains removed:** `XP25-MerlinAI-Demo` (the 9D demonstration VM), `XP25-Security-8.1` and `XP25-AI`. Their disks
  were deleted with them. The definitions were saved without secrets in `winxp_2026/.work/cleanup-20261124/domains/`.
  `XP25-AI` was removed only after the broker below was ready, and no VNC connection to it was open.
  The other VMs (`MerlinAI-Builder`, `win11-1`, `win11-2`) were not touched.
* **Disk layers deleted:** 279 `.qcow2` files across the seven worktrees' `.work/`. That covers every guest disk
  except these:
  * XP25-Winlogon-Fix's chain;
  * the MerlinAI-Builder VM's disks;
  * image-04, which is builder baseline `xp25wf4` and the Newbie template's source;
  * the reference build VMs with their whole backing chains (all 30 `boot-debug-20261022/build-*` layers are
    links in those chains).

  The deletions included the test-run disks of failed runs, 107 of them, as asked. Their `failure.json`, serial
  logs, journals and screenshots are kept, and so are all build media. Every deleted file is listed with its size,
  mtime and backing file in `winxp_2026/.work/cleanup-20261124/deleted-disks.json`. The first pass stopped when it
  tried to chmod a libvirt-owned read-only file, which unlinking does not need; the record covers both passes.
  The data disk went from 97% used to 51% (117 GiB free); about 117 GiB of 171 GiB of unique guest-disk data were
  freed (on btrfs, reflinked copies share space).
* **Old XP25-Winlogon-Fix disks** (`.289abb03`, `.f24bba5b`, `.ie8`, `.supermium`) are gone. The VM keeps two
  layers: its base and the 102 MiB layer of the FltMgr update. MerlinAI's Roll Back still works.
* **Not possible any more:** re-running the older milestones' harnesses on their frozen images (`--image m8|m81|m82|m9`,
  the XP25-AI engineering image). New work tests on image-04 and its descendants.

## XP25-Winlogon-Fix

* **FltMgr update:** applied by the user through MerlinAI. The deployment agent recorded `apply_written` and then
  `apply_healthy` at 2026-11-24T17:14:18Z. The VM runs revision `XP25-Winlogon-Fix-MerlinAI-1+J-20261124-103813-56bc78`.
* **VNC console:** now on fixed loopback port 5926 with a VNC password. The password exists only in libvirt and in
  `/home/artemd/mea-xp25-20261124/wf-vnc.pass` (0600). virt-manager asks for it once.
* **Deployment agent fix:** the agent rebuilt the domain from `virsh dumpxml --inactive`, which omits the VNC
  password. Its next Apply or Roll Back would therefore have silently removed the console password.
  * It now reads with `--security-info`, and the saved definitions are written 0600.
  * Test: `DeployAgentTests.test_disk_switch_keeps_the_console_password`.
  * The relay and the agent now run from `winxp_2026` (`~/.config/merlin/*.env`). The retired `xp25-merlin`
    worktree is no longer used; its code had been identical.
  * The agent no longer serves the demo installation.

## Newbie desktops: a fresh VM per connection

```text
MEA "XP25" card (kind xp25-ai, Guacamole connection 11, unchanged relay route)
  -> relay 10.84.0.118:5900 -> reverse SSH tunnel (xp25-tunnel) -> 127.0.0.1:5925
  -> xp25-newbie-broker: new overlay of the frozen template, transient domain XP25-Newbie,
     relays VNC to the VM's own server (127.0.0.1:5935, MEA's existing password)
  -> on disconnect: VM destroyed, overlay and COM1 log deleted
```

### Template (`remote-access/newbie_template.py`)

The template is built from image-04 (`378e9edd…8183`), never from the administrator's VM. Its parts:

* **Base:** a reflink copy of image-04, read-only.
* **The FltMgr update:** job `J-20261124-103813-56bc78`, taken from the deployment agent's stage directory and
  applied with the agent's own rules:
  * `xp25krnl.exe`: `b9531947…` replaced by `2942bd37…`;
  * `image-revision.txt`: `1c6c54da…` replaced by `276c59e7…`.
* **One setup boot** without a network adapter. XP25 is logged on, and a one-time Startup script runs:
  * gives the template its own MerlinAI installation, `xp25-newbie`. It is registered on the builder with baseline
    `xp25wf4`, and the guest never receives the XP25-Winlogon-Fix credentials;
  * removes the Supermium profile. The image's profile from 2026-11-21 had account, autofill and browsing-topics
    databases;
  * turns on automatic logon of XP25 (blank password).

  The guest is then turned off from the Start menu, and its disk is frozen.
* **Offline checks:** automatic logon, `DefaultUserName` XP25, MerlinAI installation `xp25-newbie`, the update
  files' hashes, the revision, the profile and the setup files gone. A verification boot of a throw-away overlay
  reached the desktop with no key sent (`session_interactive` 18 s after start).

Template `template-04/setup/disk.qcow2` is `9412c7c5…e274`.

Three runs failed and are kept, each with a `failure.json`:

| Run | Failure |
| --- | --- |
| `template-01` | The `browser_wait_shutdown` logon helper waits for a Winlogon record (`core_ready`) that this build does not emit. |
| `template-02` | The script used `%APPDATA%`, which is not set in an XP25 Winlogon session. The `ntfsinfo -F` existence check also exits 0 for missing files. |
| `template-03` | `if exist "...\nul"` is false for quoted paths with spaces, so the profile was not removed. |

### Broker (`remote-access/home/xp25_newbie_broker.py`, user unit `xp25-newbie-broker`)

* **Where it listens:** on 127.0.0.1:5925, where the existing tunnel delivers MEA's VNC connections. Neither the
  relay, AWS nor MEA changed.
* **What each connection gets:**
  * an overlay of the frozen template (the template's chain must be read-only and its hash must match);
  * the transient domain `XP25-Newbie`, with XP25-Winlogon-Fix's hardware profile (1 vCPU, 1 GiB, IDE, RTL8139,
    USB tablet);
  * MAC `52:54:00:25:00:09`, which leases 10.25.0.27 (the demo VM's former reservation);
  * the filter `xp25-browser-merlin`: the browser gateway, the MerlinAI relay, the deployment-agent port and the
    XP25 gateway port.
* **Browser gateway:** it now also admits 10.25.0.27.
* **Session lifetime:** one seat. A new connection ends the previous VM first, so a reconnecting browser also gets
  a fresh VM. A session also ends after 8 hours.
* **Tests:** `tests/test_remote_access.py` `NewbieBrokerTests` (4 tests).

### Observed on this host, 2026-11-24 (evidence: `.work/mea-newbie-20261124/broker-tests/`)

| Check | Result |
| --- | --- |
| Local VNC client, held 200 s | VM started and ServerInit in 1.5 s, `QEMU (XP25-Newbie)`, MEA's password accepted. Desktop with automatic logon, no hardware wizard. DHCP 10.25.0.27 (18:09:57Z). On disconnect: `session_end client_closed`, domain gone, overlay and log deleted |
| Second session, held 420 s | DHCP 24 s after start. `https://example.com` opened from Run in Supermium and the page loaded through the browser gateway. MerlinAI opened. Previous Builds made the relay forward `GET /merlin/v1/challenge` and `GET /merlin/v1/jobs` as installation `xp25-newbie` (200, no jobs). Cleaned up on disconnect |
| New connection during a session | The first client was closed by the broker after 12 s (`replaced`, VM destroyed), and the second got a fresh VM. Cleaned up |
| Whole route: SSM port forward to relay 10.84.0.118:5900, reverse tunnel, broker | RFB 3.8, VNC authentication passed, `QEMU (XP25-Newbie)` (BIOS text screen, 720×400). Cleaned up after 3 s |
| MEA registration | Connection 11 renamed `XP25`, with a description saying every connection starts a fresh machine with Internet access (`ready: true`) |

Not observed: a browser sign-in to MEA and a Guacamole session by a real Newbie account. Apply Update in a Newbie
VM is not available, because `xp25-newbie` is not an installation of the deployment agent. It was not tried in
the user interface.

### Limitations

* **Display:** 640×480 with Windows' low-resolution balloon, the same as XP25-Winlogon-Fix. XP25-AI ran at
  1024×768.
* **MerlinAI problem queue:** the template's local queue shows 19 problems collected on image-04 before it became
  the template.
* **Exposure:** while a Newbie holds the lease, they can reach any public HTTPS site from the home connection and
  can start MerlinAI builds, which spend the builder's gpt-4.1 key. Both were requested.
* **Host session:** the services run with the Linux user's session (`Linger=no`), like the existing tunnels.

## The admin-only desktop

The design uses MEA's existing private-desktop support (`adminOnly`, `adminUser`) and needs no MEA code change:

* kind `xp25-winlogon-fix`, name `XP25-Winlogon-Fix`, Guacamole connection 54, for your MEA administrator account
  only;
* relay port 10.84.0.118:5902, carried by its own restricted SSH key and its own unit `mea-xp25-admin-tunnel`
  (the Linux hypervisor's tunnel is not restarted);
* destination: XP25-Winlogon-Fix's console on 127.0.0.1:5926.

Claude Code's auto mode at first refused to change the production relay. With the user's approval the change was
then made by `/home/artemd/mea-xp25-20261124/relay_admin_xp25.py`:

* **Relay sshd:** backups first, then `sshd -t`, then a reload that keeps existing sessions. `PermitListen` now has
  `10.84.0.118:5900 10.84.0.118:5901 10.84.0.118:5902`. The new key's `authorized_keys` line is
  `restrict,port-forwarding,permitlisten="10.84.0.118:5902"`.
* **Security group** `sg-0d36f7cf397ed568a`: TCP 5902 from the Guacamole task's group `sg-0d57fd0af15df0be0` only.
  The 5900 and 5901 rules are unchanged.
* **Home:** `mea-xp25-admin-tunnel` was enabled. It authenticated to the relay and holds 5902, with no restarts.
  With `ExitOnForwardFailure`, a refused forward would have ended it.
* **XP25-Winlogon-Fix** was started.
* **Registration** (`register_mea.py admin`): first disabled (connection 54). A VNC login through the whole route
  then passed: SSM port forward to relay 5902, the tunnel, the VM's console, RFB 3.8, `QEMU (XP25-Winlogon-Fix)`,
  800×600. Then enabled.

The admin-only policy comes from the registration. The control function stores it only after resolving the named
account as a verified, active administrator, and the Guacamole guard and the API enforce it as for the Linux
hypervisor desktop. It was not audited separately: there is no read-only listing action, and no audit function was
deployed. A browser session through MEA was not observed.

The card works while XP25-Winlogon-Fix is running and the Linux user's session is up (`Linger=no`). The VM does not
start automatically.

## Reproduction

```bash
N=.work/mea-newbie-<date>
python3 components/merlin/builder/deploy/builder_vm.py register --dir <builder vm-01> \
    --installation xp25-newbie --baseline xp25wf4 > $N/keys/register.out          # 0600, once
python3 remote-access/newbie_template.py --output $N/template-NN \
    --baseline <image-04> --baseline-sha256 378e9edd71f9fc3435800ca3b0ad856a08f435e3a6b09e66d2dc32fee3e58183 \
    --update <agent state>/xp25-winlogon-fix/stage/<job> --installation-json $N/keys/register.out
# ~/.config/xp25/newbie-broker.json: template path and template_sha256 from template.json
systemctl --user restart xp25-newbie-broker
```

After every update applied to XP25-Winlogon-Fix, rebuild the template, so Newbies get the same system. Today
`newbie_template.py` applies exactly one update (`--update`). The next update needs it to accept several, applied
in order. Alternatively, a new builder baseline makes a new template source.
