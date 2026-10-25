# XP25-AI in virt-manager (disposable)

**XP25-AI** is a persistent `qemu:///system` VM, defined on 2026-10-25 for
interactive use of ClippyAI and RoverAI. Its disk is a disposable qcow2 overlay
on the verified AI image, `.work/ai-20261025/image-05/XP25-AI-Engineering.qcow2`
(SHA-256 `ec22f45b67af19f584eb6ca0a286e943731298543aa1b910eab6ff42674bee2a`,
mode 0444). That image holds native build 10 of the XP25 agent runtime, ClippyAI
and RoverAI on the accepted engineering image with the original Winlogon
([milestone record](xp25-ai-clippyai-roverai.md)). Guest writes go only to the
overlay, and the image is opened read-only.

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
| Console | VNC on `127.0.0.1`, autoport (`127.0.0.1:2` at hand-off) |
| Other | COM1 to `.work/XP25-AI-registration-20261025/serial.log`; USB, audio and balloon off; autostart disabled |

## Preservation

`register.py snapshot before/after` compared every domain and network.
- The only new domain is XP25-AI.
- No existing definition or state changed: xp25-sp3, XP25-Winlogon, win11-1,
  win11-2, win11test and XP25-Anniversary.
- The running `xp25-sp3` QEMU has the same PID, start time and command hash.
- The `default` network is unchanged. `XP25-Isolated` differs only by the added
  host line `52:54:00:25:00:05 → 10.25.0.13`.
- image-05 has the same SHA-256, size, mode, mtime and inode.

`virt-xml-validate` accepted the XML.

## Known issues

- **No IP address while another XP25 VM holds a lease.** `XP25-Isolated` has a
  DHCP range of the single address `10.25.0.10`. dnsmasq offers `10.25.0.13` to
  this VM, then NAKs its request with `no leases left`; 496 NAKs are logged in
  `dnsmasq-xp25.log` while XP25-Winlogon holds `10.25.0.12`. The guest shows
  `0.0.0.0`. `ipconfig /renew` as `XP25` returns "Access is denied". Widening the
  range would fix this, but it changes the shared network, so it was not done.
  The guest needs no network for ClippyAI's offline mode or RoverAI.
- The Windows computer name is `XP25-BASELINE`, inherited from the image and
  shared with XP25-Winlogon. Windows may report a duplicate network name if both
  are on the network at once.
- The image still carries the old third-party `OEMINFO.INI` ("Maher's Digital
  World"). Only XP25-Winlogon was rebranded
  ([xp25-winlogon-oem-branding.md](xp25-winlogon-oem-branding.md)).
- The first boot took about 4–5 minutes to reach the taskbar, against about
  90 s in the image's proof run. The cause was not investigated.

Evidence: `.work/XP25-AI-registration-20261025/` holds `register.py`, the XML,
`commands.jsonl`, `state-{before,after}.json`, `preservation.json`, `result.json`
(8 of 9 gates; the DHCP lease fails) and screenshots `01`–`08`.
