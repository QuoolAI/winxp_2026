# XP25-Winlogon in virt-manager

The persistent system libvirt VM **XP25-Winlogon** runs an independent writable
copy of the latest verified engineering image,
`engineering-image-02/XP25-Winlogon-Engineering.qcow2`. That image carries the
independent XP25 Winlogon (native build 10, SHA-256
`e3a9cdca26ab7af5ae5b225d647c94be0dc34aa4f7428e025ddf3b3c3becdf93`), which hosts
the original MSGINA on the compiled NT 5.1 x86 UP kernel/HAL. Registration did
not install, patch or reconfigure any guest component.

A serial-gated verification boot reached Winlogon `core_ready` and the MSGINA logon
dialog. LSA rejected a wrong password, and the existing `XP25` account
(blank password, unchanged) logged on. The installed `licdll` agent then admitted
the session, and Explorer's token identity was verified. Luna, the Start menu, the
taskbar, the desktop, folder navigation and Notepad all worked. The guest then
requested a normal shutdown. The VM was started again with a plain `virsh start`.
It is left **running at the logon screen**, with its console open in virt-manager.
Autostart is disabled.

## Open the VM

Use virt-manager's **QEMU/KVM** (system) connection and double-click
**XP25-Winlogon**, or run:

```bash
virt-manager --connect qemu:///system --show-domain-console XP25-Winlogon
virsh --connect qemu:///system start XP25-Winlogon      # when it is shut off
```

Log on as `XP25` with a blank password. The known Found New Hardware Wizard
appears after logon and was cancelled during verification. Shut down through
**Start → Turn Off Computer → Turn Off**.

## Virtual hardware

| Setting | Registered value |
| --- | --- |
| Connection / acceleration | `qemu:///system`, KVM, `i686` guest |
| Domain UUID | `cd4b8d14-93c5-4ee4-aa0d-2b1ef2d1a5d4` |
| CPU / memory | `qemu32` (`check='none'`), 1 vCPU (1 socket/1 core), 512 MiB; UP kernel/HAL |
| Machine / firmware | `pc-i440fx-8.2`, SeaBIOS, ACPI/APIC, KVM in-kernel IRQ chip |
| Disk | 32 GiB virtual qcow2, IDE primary master (`hda`), writeback cache |
| CD-ROM | Empty IDE secondary master (`hdc`), read-only |
| Video / input | Standard VGA, 16 MiB; PS/2 keyboard and mouse |
| Console | VNC on `127.0.0.1`, autoport (`127.0.0.1:5901` / display `:1` at hand-off) |
| NIC | RTL8139, PCI slot 3, MAC `52:54:00:25:00:04` |
| Network | Existing isolated `XP25-Isolated` (`virbr-xp25`); DHCP reservation `10.25.0.12` (`xp25-winlogon`) |
| DHCP / DNS / route | Server `10.25.0.1`; `xp25.test` resolves locally; no default gateway |
| Other | Local-time RTC; COM1 file backend; USB, audio backend and balloon disabled |
| Lifecycle | Persistent; poweroff destroys, reboot restarts, crash preserves; autostart disabled |

This is the profile that `launch-native.py up` used for the 18-gate UP-KVM
verification (`-machine pc-i440fx-8.2,kernel-irqchip=on -accel kvm -cpu qemu32
-m 512 -smp 1 -vga std`, IDE disk and CD-ROM, local-time RTC). The generated QEMU
command is saved in `libvirt-qemu-command.txt`.

## Storage and identity

Paths are relative to the project root:

- Source (read-only, mode 0444, never attached): `.work/winlogon-licensing-20261025/engineering-image-02/XP25-Winlogon-Engineering.qcow2`,
  SHA-256 `0df7fc05b0b965941f4c488894ce200adcd44d91acf4bf28f93f7a445d30c51c`
- VM disk: `.work/virt-manager-XP25-Winlogon-20261025/XP25-Winlogon-Desktop.qcow2`
- Registration XML, commands, screenshots and evidence: `.work/XP25-Winlogon-registration-20261025/`

The disk is a full byte copy (`cp --reflink=never --sparse=always`) with its own
inode. Before boot its SHA-256 equalled the source's. `qemu-img compare` reports
the images identical, and `qemu-img check` passes before and after boot. Its chain
has no backing file, and `btrfs filesystem du` reports 0 bytes shared with any
other file. Guest use now changes only this copy.

The VM has its own UUID, MAC address, DHCP reservation, disk and serial log. The
guest's Windows computer name, inherited with the disk, is still `xp25-baseline`,
the same name used by the earlier clones. Changing it would modify guest
configuration, so it was left unchanged. Windows may report a duplicate network
name if another clone with that name is running on `XP25-Isolated` at the same
time.

## Verification evidence

`commands.jsonl` records every host command with its output. `result.json` holds 27
gates, all passing. On the verification boot, COM1 was redirected to a 1 MiB QEMU
ring buffer before the guest ran (start paused → `chardev-change` → resume). This
was needed because libvirt makes the file backend root-only. Gates are decided
from those guest records (`verify-serial.log`); screenshots are evidence only.

- `01-logon-screen.png`: the independent Winlogon reaches `core_ready` and shows
  MSGINA's *Log On to Windows* dialog with user `XP25`.
- `02-wrong-password-rejected.png`: LSA rejects `XP25-Invalid-Runtime-2026`; no
  session starts.
- The valid logon records `profile_hive_identity_verified`,
  `licensing_policy_verified`/`licensing_policy_allowed` (`WPALeft` 2147483647
  from `licdll`), `user_shell_activation_success`,
  `explorer_token_identity_verified` and `session_interactive`.
- `03-desktop-after-logon.png`, `04-wizard-cancelled.png`: Explorer/Luna desktop.
- Probes from a private copy of `checks.iso` (SHA-256 `485a9bd5…660d`), inserted
  for this boot only and ejected afterwards. `xp_probe` passes six observations,
  with zero failures and its four by-design `not_tested` cases. `session_probe`
  passes six cases (XP25 primary token, Explorer in the same logon session,
  visible `WinSta0\Default`). `shell_probe` passes fourteen cases (desktop and
  taskbar, live Explorer image, Start menu opens, Luna active, folder window
  lists a fixture, taskbar survives). Exit codes come from delayed expansion
  (`!ERRORLEVEL!`) and are all 0.
- `05-start-menu.png`, `06-notepad-taskbar.png`, `07-notepad-save-prompt.png`,
  `08-desktop-verified.png`: keyboard-opened Start menu. Notepad was launched
  from it, edited and shown with its taskbar button, then closed without saving.
- Network: guest `ipconfig /all` reports `52-54-00-25-00-04`, DHCP `10.25.0.12/24`,
  server/DNS `10.25.0.1` and no gateway. `ping xp25.test` gets 2/2 replies.
  libvirt's lease table independently shows the same MAC/IP (`dhcp-lease.txt`).
- `shutdown-event.log`: QEMU `SHUTDOWN {"guest":true,"reason":"guest-shutdown"}` at
  2026-10-25 11:40:15 UTC, following Start → Turn Off Computer → Turn Off.
- `component-retention.json`: an offline read-only `ntfscat` check after shutdown.
  All 22 components in the engineering verification record are byte-identical,
  including `winlogon.exe`, `xp25krnl.exe`, `xp25hal.dll`, `msgina.dll`,
  `ntdll.dll`, `win32k.sys`, `explorer.exe` and `boot.ini`.
- `preservation-after-verification.json`: the source image hash, size, mode,
  mtime and inode are unchanged. The five remaining pre-existing domain
  definitions and states are unchanged, as is the running `xp25-sp3` QEMU
  (PID, start time, command hash). The `default` network is unchanged, and
  `XP25-Isolated` differs only by the added `xp25-winlogon` reservation.
- Hand-off boot: plain `virsh start` without monitor commands. libvirt logs no
  taint for it, and `10-handoff-logon-screen.png` shows the logon dialog again.
  This boot's COM1 goes to the root-owned `serial.log`, so the hand-off boot
  has screenshot evidence only.
- `virt-manager --show-domain-console` returns 0, and virt-manager's log
  records its VNC viewer connecting to `127.0.0.1:5901`.

## Deviations, failures and limits

- The verification boot is marked `custom-monitor` tainted in libvirt because of
  the ring-buffer redirect, key input and media changes made through the monitor.
  The persistent definition never changed. The VM left running is the later,
  untainted boot.
- One ring-buffer read was attempted after QEMU had already exited. It failed
  with `domain is not running` and is retained in `commands.jsonl`; it decided no
  gate.
- `service_probe` (installs a fixture service) and `network_probe` (expects
  `10.25.0.10`) were deliberately not run in this long-lived VM. Lock/unlock,
  Task Manager, Windows Security, Explorer crash recovery, logoff/re-logon, MP
  and TCG were not repeated here. They remain covered by the engineering image's
  independent 18-gate proof, not by this registration.
- **External change during registration:** at 2026-10-25 04:28:27–04:29:02 local,
  the interactive virt-manager *Delete* wizard (PID 6464) deleted
  `XP25-Desktop.qcow2` and undefined **XP25-Desktop**. This happened before this
  registration defined its domain (04:34:21). No command in this registration
  touched XP25-Desktop except to read its XML. The excerpt is saved as
  `external-XP25-Desktop-removal-virt-manager.log`. Its `.10` DHCP reservation
  was left as it was.
- Known Winlogon gaps still apply (see [winlogon-desktop-session.md](winlogon-desktop-session.md)):
  Terminal Services session state, no Welcome screen, Fast User Switching or event
  sounds, an unthemed logon desktop, and post-logoff GINA edits that do not paint.
  The Found New Hardware Wizard recurs because it was cancelled, not resolved.
  Display stays at the inherited 640×480.
- This registration makes no new hardware, graphics, game, Internet, TLS/IPv6 or
  long-run stability claim. Licensing/provenance acceptance of the engineering
  image is still pending, as its README states.
