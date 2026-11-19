# XP25-Winlogon-Fix in virt-manager

**XP25-Winlogon-Fix** is a persistent `qemu:///system` VM, defined on 2026-11-18
for interactive use of the account-switching fix
([root cause and verification](winlogon-account-switch-paint.md)). Its disk is a
copy of the engineering image
`.work/winlogon-vm-20261118/image-01/XP25-Winlogon-Fix-8.2.qcow2`
(SHA-256 `fe633d1570f042b3cc8f869ad0fe1f6fabfc0e048ab57437b8d5c6e89f1ec173`).

## The image

The image is the accepted Milestone 8.2 image `XP25-CVE-Hardened-8.2`
(`5a84781f3adee8861f8b7e3cd5b57ee11778e87a3b7683111ebf9e31ba80eada`,
[record](historical-cve-remediation.md)) with exactly one file changed:
`\WINDOWS\system32\winlogon.exe`, from the unfixed XP25 Winlogon `e3a9cdca…` to
the fixed build `f24bba5b2561b183a33d1cda106941138c28b1cc8dc50fde79f23f4511f733d3`
(commit `558cd3cda`, native build `wl-build-15`, collection
`W16/collect-wl-build-15/files.json`). Everything else is the 8.2 image:
security baseline version 2, the `lsasrv.dll` MS04-011 fix, ClippyAI and RoverAI
(AI build 14).

`build/winlogon_package_image.py` made it:

```sh
W=.work/winlogon-vm-20261118
cp --reflink=always <xp25-cve>/.work/cve82-20261112/image-82/XP25-CVE-Hardened-8.2.qcow2 $W/reference/   # then chmod 0444
python3 build/winlogon_package_image.py --parent $W/reference/XP25-CVE-Hardened-8.2.qcow2 \
  --parent-sha256 5a84781f3adee8861f8b7e3cd5b57ee11778e87a3b7683111ebf9e31ba80eada \
  --expect-installed e3a9cdca26ab7af5ae5b225d647c94be0dc34aa4f7428e025ddf3b3c3becdf93 \
  --winlogon .work/winlogon-ui-20261116/winlogon-fix02.exe \
  --collect .work/winlogon-ui-20261116/collect-wl-build-15/files.json \
  --name XP25-Winlogon-Fix-8.2.qcow2 --output $W/image-01
```

The script refuses a parent that is writable, has a backing file or does not
match its hash. It also refuses a `winlogon.exe` that is not the one recorded
by its native build collection, or an installed file that is not the expected
unfixed build. It overwrites the file offline with `ntfscp`, which keeps the
file's NTFS security descriptor. It then reads the file back, runs
`qemu-img check` (no errors), sets the image read-only and re-hashes the parent
(unchanged). `$W/image-01/manifest.json` records the lineage.
`\WINDOWS\system32\dllcache\winlogon.exe` is still Microsoft's `7cd68891…`, as
in every earlier XP25 image; the XP25 Winlogon does not load SFC, so nothing
restores it.

**Image verification.** The two-account oracle ran against this exact image,
with no staged files, on one-vCPU KVM:

```sh
python3 vm/winlogon_switch_probe.py --name image01-2acct-up-01 --image $W/image-01/XP25-Winlogon-Fix-8.2.qcow2 \
  --image-sha256 fe633d1570f042b3cc8f869ad0fe1f6fabfc0e048ab57437b8d5c6e89f1ec173 \
  --probe .work/winlogon-ui-20261113/security_probe.exe --second-user XP25B --second-password sw1tch25 \
  --wrong-password-cycle 3 --cycles 10 --out-root $W/runs
```

It **passed**: 9/9 switches had both fields painted, early and late. The two
accounts alternated (XP25 ↔ XP25B) across 10 logons with no input retries, and
the wrong password was refused. Evidence: `$W/runs/image01-2acct-up-01/`. The
two-vCPU KVM and TCG results, and the lifecycle, lock/unlock, restart and
shutdown gates, are the overlay runs of the same binary on the 8.1 image
([verification](winlogon-account-switch-paint.md#verification)). The only
difference from the 8.2 image is the 8.2 `lsasrv.dll`. They were not repeated
on this image.

## The VM

Defined and started with `virsh start`, and left **running at the logon
dialog**. It was driven only through libvirt's public API (`vm/libvirt_ui.py`:
send-key and screenshot); COM1 goes to a file libvirt makes root-only. Observed
by screenshot (`01`–`08`):

1. After boot, the logon dialog had `XP25` filled in and both fields painted.
2. Enter with the blank password reached the `XP25` desktop (Luna, ClippyAI
   shortcut). The Found New Hardware Wizard opened at this first logon, as in the
   8.1 VM, and was cancelled. Windows warned that the display runs at 640×480.
3. **Start → Log Off → Log Off:** the logon dialog came back with both fields
   painted.
4. Logged on again (desktop reached), then logged off again: the dialog came
   back painted once more. The stock Winlogon fails on every other logoff, so
   these two logoffs cover both halves of the old alternation.

The guest leased `10.25.0.26` from `XP25-Isolated`. No probe ran in this VM.
Its image was verified by the oracle run above.

## Open, reset, remove

```bash
virt-manager --connect qemu:///system --show-domain-console XP25-Winlogon-Fix
virsh --connect qemu:///system start XP25-Winlogon-Fix        # when it is shut off
```

Log on as `XP25` (administrator, blank password). Logging off and logging on
again, including as another account, now works without a restart. Use **Log
Off**, not **Switch User**: Fast User Switching is not implemented by the XP25
Winlogon ([known gaps](winlogon-desktop-session.md#known-gaps-and-defects)). Shut down or
restart through **Start → Turn Off Computer**: `shutdown.exe` does not work
under the XP25 Winlogon.

To reset the VM to the packaged image, shut it down, then replace the copy
(paths relative to the `xp25-winlogon-ui` worktree):

```bash
D=.work/virt-manager-XP25-Winlogon-Fix-20261118
rm $D/XP25-Winlogon-Fix.qcow2
cp --reflink=always .work/winlogon-vm-20261118/image-01/XP25-Winlogon-Fix-8.2.qcow2 $D/XP25-Winlogon-Fix.qcow2
chmod 0644 $D/XP25-Winlogon-Fix.qcow2
```

Nothing uses the copy as a backing file. `virsh undefine XP25-Winlogon-Fix`
removes the VM.

## Definition

The definition matches [XP25-Security-8.1](virt-manager-xp25-security-81.md#definition),
except:

| Setting | Value |
| --- | --- |
| Disk | `XP25-Winlogon-Fix.qcow2` (IDE `hda`, writeback), a standalone reflink copy. It hashed equal to the image before the first boot |
| NIC | RTL8139, MAC `52:54:00:25:00:07`, network `XP25-Isolated`, filter `xp25-gateway-only` (`GATEWAY_IP` 10.25.0.1, `GATEWAY_PORT` 8443). No route off the host |
| Profile | KVM `i686`, `pc-i440fx-8.2`, `qemu32`, **1 vCPU** (the image boots the uniprocessor kernel and HAL), 512 MiB |
| Console | VNC on the host's loopback interface only, autoport. COM1 to `serial.log` (root-only while libvirt runs it) |

`virt-xml-validate` accepted the XML.

## Preservation

`register.py snapshot before/after` hashed every domain, network and filter
definition and recorded every running QEMU process. `register.py compare`:

* the only new domain is XP25-Winlogon-Fix;
* no other domain, network (`default`, `XP25-Isolated`) or filter definition changed;
* the running XP25-AI QEMU has the same PID, start time and command;
* the packaged image still hashes `fe633d15…` and is mode 0444.

XP25-Security-8.1, its disk and the 8.1 and 8.2 accepted images were not
touched.

Evidence: `.work/virt-manager-XP25-Winlogon-Fix-20261118/` holds `register.py`
(the 8.1 script with this VM's names and hashes), the XML, `commands.jsonl`,
`disk.json`, `state-{before,after}.json`, `preservation.json` and the
screenshots.
