# Interactive XP25 desktop in virt-manager

The persistent system libvirt VM **XP25-Desktop** uses an independent disposable
copy of the latest verified desktop checkpoint, `network-native-kvm-mp-02`,
frozen at 2026-10-23 18:35:27 UTC. Its original Microsoft components, source-built
MP kernel/HAL, Winsock helper, registry and boot configuration were copied with
the entire disk. No guest components were installed or patched for registration.

The VM reached Explorer/Luna and passed the four existing probe suites. It was
shut down through Windows and is left **shut off**, with VM autostart disabled.
Its graphical console was opened using virt-manager's console command.

## Open and start

Use the **QEMU/KVM system** connection in virt-manager, select **XP25-Desktop**,
open its console and click the start button. The equivalent commands are:

```bash
virt-manager --connect qemu:///system --show-domain-console XP25-Desktop
virsh --connect qemu:///system start XP25-Desktop
```

The inherited desktop account is `XP25`; its credentials are kept outside the repository. The known Found
New Hardware Wizard can appear; it was cancelled during verification. Keep the
existing display settings; accelerated graphics remain unverified. Shut down
through the Windows Start menu when finished.

## Preserved configuration and storage

| Setting | Registered value |
| --- | --- |
| Domain UUID | `74893182-ab36-47ef-b6e0-c689547ece30` |
| Connection / acceleration | `qemu:///system`, KVM, i686 |
| Machine / firmware | `pc-i440fx-8.2`, BIOS, ACPI/APIC, KVM IRQ chip |
| CPU / memory | `qemu32`, two vCPUs, one socket/two cores, 512 MiB |
| Disk | 32 GiB virtual qcow2, IDE primary master, writeback cache |
| CD-ROM | IDE secondary master, existing read-only network regression ISO |
| Video / input | Standard VGA, 16 MiB video RAM; PS/2 mouse and keyboard |
| Network device | RTL8139, PCI slot 3, MAC `52:54:00:25:00:02` |
| Network backend | Existing isolated `XP25-Isolated` libvirt bridge |
| Address / DHCP / DNS | `10.25.0.10/24`, server `10.25.0.1`; `xp25.test` resolves locally |
| Console | VNC bound to `127.0.0.1`, automatically assigned display port |
| Clock / serial | Local time; COM1 retained |
| Other devices | USB, sound backend and memory balloon disabled |
| Lifecycle | Windows reboot restarts the VM; normal shutdown stops it; no autostart |

The isolated network has no forwarding configuration, reads no upstream DNS
resolver, and advertises no default router. It was already active and was reused
without changing its definition. The namespace-based test guests remain separate.
The HTTP server at `10.25.0.1:8080` was a temporary validation fixture and was
stopped after testing; DHCP/DNS remain available through libvirt.

Paths relative to the project root:

- Reference: `.work/boot-debug-20261022/network-native-kvm-mp-02/disk.qcow2`
- Disposable disk: `.work/virt-manager-XP25-Desktop-20261023/XP25-Desktop.qcow2`
- Read-only CD: `.work/virt-manager-XP25-Desktop-20261023/network-tests.iso`
- Final registration and evidence: `.work/XP25-Desktop-registration-20261023/`

The disposable disk has **no backing file**. Its pre-boot SHA-256 was
`6c6775ec329d441deb1de78945499f190479c7d9d3819607824ea1f2bf12dd5b`.
Its container hash differs from the reference because it is flattened; the
guest-visible sectors compare identically. Normal guest use changes this copy.
The source SHA-256 remains
`96ae34bf4c66cb79a1211c6c29e4cf2e48dde99697ed00efe8ce4588657b1940`.

## Executed verification and limitations

`commands.jsonl` records executed registration/verification commands and their
outputs. `journal.jsonl` records guest input and screenshots. The earlier copy's
conversion command and log remain in its preparation directory. Evidence includes:

- `independent-copy-compare.log`: `qemu-img compare` reports images identical.
- `copy-chain.json` and `copy-chain-after.json`: one independent image, no backing.
- `image-check-before.log` and `image-check-after.log`: qcow2 checks pass.
- `XP25-Desktop.registered.xml`: final persistent definition; XML validation passes.
- `libvirt-qemu-command-final.txt`: generated QEMU command retains the recorded
  guest hardware settings. A small diskless QEMU run confirms the original
  `-smp 2` topology is one socket/two cores.
- `verified-desktop.png`: Explorer/Luna at the inherited 640×480 resolution.
- `probe-serial.log`: six standard, eleven pointer, six session and seventeen
  networking observations pass, with all four executable exit records zero.
  The session probe identifies XP25 and its Explorer logon session. A separate
  manual logoff/login transition was not repeated for this registration.
- `dhcp-lease.txt`, `http.jsonl`: independent lease and HTTP request evidence.
- `shutdown-event.log`: QEMU reports `guest=true`, `reason=guest-shutdown` at
  2026-10-23 19:05:37 UTC, following guest `shutdown.exe -s -t 0`.
- `reference-preservation.json` and `reference-chain-sha256-after.txt`: recorded
  frozen reference hashes and file metadata are preserved. No reference disk is
  attached to this domain.
- `existing-guests-preserved.json`: all four pre-existing persistent domain
  definitions are unchanged; the running `xp25-sp3` QEMU PID, command and start
  time are unchanged. The isolated network definition also remains unchanged.

The first startup was rejected before guest execution because libvirt's
`check=full` CPU validation rejected QEMU's additional `x2apic,hypervisor` flags.
Using `check=none`, as in the existing XP domain, preserves the actual
`-cpu qemu32` command and boots successfully. The rejected XML and error remain
in the evidence directory. During verification libvirt's permissions prevented
the host user from reading the active COM1 file; the test run temporarily
captured the same COM1 stream through QEMU's ring buffer. The persistent serial
definition is unchanged. An initial host hash helper was corrected for Python
3.10; its failure is recorded separately.

This is an interactive registration of the verified native desktop, not a new
OS rebuild or evidence for additional hardware, accelerated graphics, games,
TLS, IPv6, Internet access or sustained stability. The existing Microsoft runtime
and supplied executive-object limitations described in the desktop/networking
milestone records still apply.
