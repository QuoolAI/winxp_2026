# XP25-Security-8.1 in virt-manager

**XP25-Security-8.1** is a persistent `qemu:///system` VM, defined on 2026-11-12
for interactive use of the accepted Milestone 8.1 image,
`.work/security81-20261112/image-81-02/XP25-Security-Baseline-8.1.qcow2`
(SHA-256 `501c79862d41824a2748c96f5b4715f22ba25443630cb1e3ff0c13674999fda4`,
[record](security-regression.md#milestone-81--stabilization-firewall-verification-and-final-acceptance)):
security baseline version 2, the XP25 Winlogon, ClippyAI and RoverAI (AI build 14).

Its disk is a standalone reflink copy of that image, not an overlay. libvirt
changes the owner of every file in a running VM's disk chain (XP25-AI's backing
image is owned by `libvirt-qemu` while it runs), so the VM does not reference
the accepted image at all. The copy hashed equal to the image before the first
boot, and costs no space until the guest writes.

Started with `virsh start` and left **running**. Observed by screenshot only
(COM1 goes to a file libvirt makes root-only): the XP25 Winlogon logon dialog
with `XP25` filled in; Enter with the blank password passed licensing admission
and reached the `XP25` desktop (Luna, ClippyAI shortcut). The Found New Hardware
Wizard opened at the first logon and was cancelled; Windows warned that the
display runs at 640×480. The guest leased `10.25.0.25` from `XP25-Isolated`. No
probe was run in this VM; the image's acceptance comes from the 8.1 runs.

## Open, reset, remove

```bash
virt-manager --connect qemu:///system --show-domain-console XP25-Security-8.1
virsh --connect qemu:///system start XP25-Security-8.1        # when it is shut off
```

Log on as `XP25` (administrator, blank password). Shut down or restart through
**Start → Turn Off Computer**: `shutdown.exe` does not work under the XP25
Winlogon. To change accounts, restart instead of logging off: after a logoff
the logon dialog does not paint its fields
([known gap](winlogon-desktop-session.md#known-gaps-and-defects)).

To reset the VM to the accepted image, shut it down, then replace the copy
(paths relative to the `xp25-security` worktree):

```bash
D=.work/virt-manager-XP25-Security-81-20261112
rm $D/XP25-Security-8.1.qcow2
cp --reflink=always .work/security81-20261112/image-81-02/XP25-Security-Baseline-8.1.qcow2 $D/XP25-Security-8.1.qcow2
chmod 0644 $D/XP25-Security-8.1.qcow2
```

Nothing uses the copy as a backing file. `virsh undefine XP25-Security-8.1`
removes the VM.

## Definition

| Setting | Value |
| --- | --- |
| UUID | Assigned by libvirt at `define` (`virsh domuuid XP25-Security-8.1`) |
| Profile | Same as the 8.1 lab and XP25-AI: KVM `i686`, `pc-i440fx-8.2`, `qemu32` (`check='none'`), 1 vCPU, 512 MiB, ACPI/APIC, local-time RTC. One vCPU because the image boots the uniprocessor kernel and HAL; the lab's two-vCPU runs install the multiprocessor pair into each run's overlay |
| Disk | `XP25-Security-8.1.qcow2` (IDE `hda`, writeback), standalone |
| CD-ROM | Empty IDE `hdc` |
| NIC | RTL8139, MAC `52:54:00:25:00:06`, network `XP25-Isolated` with XP25-AI's filter `xp25-gateway-only` (`GATEWAY_IP` 10.25.0.1, `GATEWAY_PORT` 8443): DHCP, DNS and ping to the host and TCP 8443 only, no route off the host. Dynamic lease from `10.25.0.20`–`.29`; no reservation was added |
| Console | VNC on the host's loopback interface only, autoport |
| Other | COM1 to `serial.log` (root-only); USB tablet; audio and balloon off; autostart disabled |

The guest still reports the inherited computer name `XP25-BASELINE` to DHCP.
The filter drops everything that is not to or from 10.25.0.1, so it does not
meet XP25-Winlogon or XP25-AI on the bridge.

## Preservation

`register.py snapshot before/after` hashed every domain, network and filter
definition and recorded every running QEMU process; `register.py compare`:

- the only new domain is XP25-Security-8.1;
- no other domain, network (`default`, `XP25-Isolated`) or filter definition changed;
- the running XP25-AI QEMU has the same PID, start time and command;
- the accepted image has the same SHA-256, owner and mode 0444.

`virt-xml-validate` accepted the XML.

Evidence: `.work/virt-manager-XP25-Security-81-20261112/` holds `register.py`,
the XML, `commands.jsonl`, `disk.json`, `state-{before,after}.json`,
`preservation.json` and screenshots `01`–`03`.
