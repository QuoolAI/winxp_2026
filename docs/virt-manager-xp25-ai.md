# XP25-AI in virt-manager (disposable)

**XP25-AI** is a persistent `qemu:///system` VM, defined on 2026-10-25 for
interactive use of ClippyAI and RoverAI. Its disk is a disposable qcow2 overlay
on the verified AI image, `.work/ai-20261025/image-05/XP25-AI-Engineering.qcow2`
(SHA-256 `ec22f45b67af19f584eb6ca0a286e943731298543aa1b910eab6ff42674bee2a`,
mode 0444). That image holds native build 10 of the XP25 agent runtime, ClippyAI
and RoverAI on the accepted engineering image with the original Winlogon
([milestone record](xp25-ai-clippyai-roverai.md)). Guest writes go only to the
overlay, and the image is opened read-only.

(Update, 2026-10-25: see [xp25-vm-configuration.md](xp25-vm-configuration.md) for its name, address and branding.)

It was started with `virsh start` and is left **running**. It logged on to the
`XP25` desktop by itself and shows the ClippyAI shortcut. The recurring Found New
Hardware Wizard for the standard VGA controller was cancelled, as on
XP25-Winlogon. This boot has only screenshot evidence: COM1 goes to a root-only
file, and no probe was run. The image's 62-case acceptance comes from its earlier
proof run (`ai-b10-image-proof-01`), not from this VM.

## Open, reset, remove

```bash
virt-manager --connect qemu:///system --show-domain-console XP25-AI
virsh --connect qemu:///system start XP25-AI            # when it is shut off
```

Shut down through **Start → Turn Off Computer → Turn Off**. To reset the VM to
the verified image, shut it down, then recreate the overlay:

```bash
qemu-img create -f qcow2 -F qcow2 \
  -b .work/ai-20261025/image-05/XP25-AI-Engineering.qcow2 \
  .work/virt-manager-XP25-AI-20261025/XP25-AI-Disposable.qcow2
```

Delete the old overlay first. Paths are relative to the `xp25-ai` worktree. The
overlay refers to image-05 by absolute path, so the VM needs that worktree's
`.work/` to stay in place.

## Definition

| Setting | Value |
| --- | --- |
| UUID | `6aa89bc8-4f1b-4642-b5ea-131ab9a06d24` |
| Profile | Same as XP25-Winlogon: KVM `i686`, `pc-i440fx-8.2`, `qemu32` (`check='none'`), 1 vCPU, 512 MiB, ACPI/APIC, local-time RTC |
| Disk | `XP25-AI-Disposable.qcow2` (IDE `hda`, writeback) → backing image-05 (qcow2, read-only) |
| CD-ROM | Empty IDE `hdc` |
| NIC | RTL8139, MAC `52:54:00:25:00:05`, network `XP25-Isolated`, reservation `10.25.0.13` (`xp25-ai`) |
| Console | VNC on the host's loopback interface only, autoport |
| Other | COM1 to `.work/XP25-AI-registration-20261025/serial.log`; USB, audio and balloon off; autostart disabled |

## Preservation

`register.py snapshot before/after` compared every domain and network.
- The only new domain is XP25-AI.
- No existing definition or state changed: xp25-sp3, XP25-Winlogon,
  XP25-Anniversary and the other registered domains.
- The running `xp25-sp3` QEMU has the same PID, start time and command hash.
- The `default` network is unchanged. `XP25-Isolated` differs only by the added
  host line `52:54:00:25:00:05 → 10.25.0.13`.
- image-05 has the same SHA-256, size, mode, mtime and inode.

`virt-xml-validate` accepted the XML.

## Known issues

These issues were fixed on 2026-10-25 ([configuration record](xp25-vm-configuration.md)):

- **No IP address while another XP25 VM held a lease.** `XP25-Isolated`'s single-address DHCP range
  allowed only one concurrent lease, and dnsmasq NAKed this VM with `no leases left`. The guest's
  "Access is denied" from `ipconfig /renew` came from those NAKs. A second range, `10.25.0.20`–`.29`,
  was added live; the VM now holds `10.25.0.13` while XP25-Winlogon holds `10.25.0.12`.
- **Shared computer name.** The name `XP25-BASELINE` was inherited and shared with XP25-Winlogon. It is now `XP25-AI`.
- **Third-party OEM text.** The overlay now carries the QuoolAI `OEMINFO.INI`, Help and Support copy
  and widened `sysdm.cpl`, with backups in `C:\xp25\vmconfig-20261025\backup`. Image-05 itself is
  unchanged and still has the third-party file, so recreating the overlay brings it back.

Still open:

- The first boot took about 4–5 minutes to reach the taskbar, against about
  90 s in the image's proof run. The cause was not investigated.

Evidence: `.work/XP25-AI-registration-20261025/` holds `register.py`, the XML,
`commands.jsonl`, `state-{before,after}.json`, `preservation.json`, `result.json`
(8 of 9 gates; the DHCP lease fails) and screenshots `01`–`08`.
