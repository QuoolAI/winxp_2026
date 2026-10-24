# XP25-Anniversary in virt-manager

The persistent system libvirt VM **XP25-Anniversary** is verified and left
**shut off**, ready for interactive startup, with autostart disabled. It uses an
independent disposable copy of `brand-final-tcg-01`, the newest verified XP25 desktop,
frozen at 2026-10-24 00:00:23 UTC. This includes the native NT 5.1 x86 UP
kernel/HAL, original SCM/SMSS, native Winsock helper and verified XP25 branding.
Guest files, registry settings and boot configuration are copied with the disk;
no system component is installed or patched for registration.

## Start interactively

In virt-manager's **QEMU/KVM system** connection, select **XP25-Anniversary**,
open the graphical console and click Start. Equivalent commands:

```bash
virt-manager --connect qemu:///system --show-domain-console XP25-Anniversary
virsh --connect qemu:///system start XP25-Anniversary
```

The inherited account is `XP25`, with a blank password. Shut down through
Windows when finished. Standard VGA and the inherited 640x480 layout are retained;
the previously observed Found New Hardware Wizard may appear.

## Disk and configuration

| Setting | New VM |
| --- | --- |
| Connection / acceleration | `qemu:///system`, KVM, i686 |
| Domain UUID | `0dce713c-a836-4ca1-b127-8561519bdc4c` |
| CPU / memory | `qemu32`, one vCPU, 512 MiB; original UP kernel/HAL retained |
| Machine / firmware | `pc-i440fx-8.2`, BIOS, ACPI/APIC, KVM IRQ chip |
| Storage | Independent 32 GiB virtual qcow2; IDE primary master, writeback cache |
| CD-ROM | IDE secondary master, read-only registration regression ISO |
| Video / input | Standard VGA, 16 MiB; PS/2 keyboard and mouse |
| Console | Automatically assigned VNC display, bound to `127.0.0.1` |
| NIC | RTL8139, original PCI slot 3; unique clone MAC `52:54:00:25:00:03` |
| Network | Existing isolated `XP25-Isolated`; DHCP lease `10.25.0.11/24` |
| DHCP / DNS | Existing server `10.25.0.1`; `xp25.test` resolves locally |
| Other | Local-time clock, COM1; USB/audio backend/balloon disabled |
| Lifecycle | Persistent domain; no autostart; normal guest reboot restarts it |

The source was most recently verified under TCG; the same original UP kernel/HAL
also passed the branding KVM matrix. Registration uses KVM and validates this
new independent copy again. It does not switch to the MP kernel or change the
guest's installed files to match a different CPU count.

The clone has its own UUID, MAC and DHCP reservation, avoiding duplicate MAC/IP
addresses with `XP25-Desktop`. The previous `.10` reservation, bridge, DNS and isolation settings
remain intact. No public forwarding, upstream DNS or default router is added.
The guest retains DHCP and its original computer/account names. Its test CD
changes only the network probe's expected client IP from `.10` to `.11`; this is
a private test-source copy, with no project source or guest OS modification.

Paths relative to the project root:

- Reference: `.work/boot-debug-20261022/brand-final-tcg-01/disk.qcow2`
- New disk: `.work/virt-manager-XP25-Anniversary-20261023/XP25-Anniversary.qcow2`
- Test CD: `.work/virt-manager-XP25-Anniversary-20261023/anniversary-tests.iso`
- Registration XML, commands, hashes and evidence: `.work/XP25-Anniversary-registration-20261023/`

The reference SHA-256 is
`d4fa9505a725fcc670ddfd443d4179e5871ef32d27d8073e6e7e04f6b4774f85`.
The copied disk has no backing image; reference disks are never attached to the
new domain. Its container hash can differ after flattening, so preboot guest
sector equality is checked separately. Normal guest use changes only this copy.
Its preboot container SHA-256 is
`eaedff3f7ef47055356848307d88ae866f88a642876157f183776e7e35bfb269`.

## Evidence and limits

`commands.jsonl` and `journal.jsonl` record registration commands, guest input and
screenshots. `result.json` and `evidence-sha256.json` summarize these checks:

- qcow2 integrity passes before and after boot; `qemu-img compare` reports all
  guest-visible sectors identical before boot; both chain inventories contain
  only the independent disk, with no backing image.
- Domain XML validates. The generated QEMU command retains the original CPU,
  memory, machine, IDE/VGA/RTL8139 profile. The virt-manager console request
  returns zero; VNC binds to loopback and uses an automatically assigned display.
- Explorer/Luna and the branded About Windows dialog are visually observed.
  Six standard, eleven pointer, six session, seventeen networking, fourteen
  service and seventeen branding observations pass. The service and branding
  probes complete, Calculator arithmetic and the own Win32 installer fixture
  pass, and the MSI fixture installs/uninstalls successfully. All twelve exit
  records are zero, including the shutdown fixture.
- DHCP independently reports MAC `52:54:00:25:00:03` at `10.25.0.11`. Controlled
  DNS, TCP/UDP and isolated HTTP pass. The temporary HTTP server is stopped;
  persistent libvirt DHCP/DNS remain available. No Internet route is added.
- A temporary loopback debugger confirms the loaded `XP25KRNL.EXE` checksum
  matches the compiled original UP kernel. Sixteen kernel/HAL, Win32, NTFS,
  networking, SCM/SMSS and branding files retain their exact reference bytes
  after shutdown. Captured compatibility/licensing identity values match the
  reference. No licensing mechanism is changed.
- Windows `shutdown.exe -s -t 0` causes the 2026-10-24 00:53:12.797 UTC
  `guest=true, reason=guest-shutdown` event. Libvirt then cleans up QEMU under
  its normal poweroff policy. The service fixture's flushed shutdown proof is
  extracted offline. No forced guest poweroff is used.
- All fifteen source-chain image hashes, sizes, modes and modification times
  are preserved. All five
  pre-existing domain XMLs and the running `xp25-sp3` PID/start time/command are
  unchanged. Network configuration differs only by the new clone reservation.

The first network preservation comparison included libvirt's live
`connections=1` counter; comparing the inactive configuration resolves that
checker issue. Initial offline kernel extraction used uppercase module paths;
`ntfscat` requires the actual lowercase filenames. Correct-case extractions
pass. These failed host checks remain recorded and are not guest failures.
During verification only, COM1 capture uses a QEMU ring buffer because libvirt
owns active log files. The persistent COM1 definition remains a file backend.
The debugger endpoint is also temporary; it closes when the test guest exits
and is not part of the persistent definition.

Automatic XP25 login and the matching Explorer interactive session are verified;
a separate manual logoff/login transition and Notepad text edit are not repeated
for this registration. Concurrent Windows file sharing, games, acceleration,
TLS/IPv6, non-English/high-DPI layouts and sustained/security workloads are not
newly tested. This registration does not expand the project's compatibility or
source-completeness claims.
