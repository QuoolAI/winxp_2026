# XP25-Winlogon-Fix in virt-manager

**XP25-Winlogon-Fix** is a persistent `qemu:///system` VM, defined on 2026-11-18
for interactive use of the account-switching fix
([root cause and verification](winlogon-account-switch-paint.md)). Its disk was
first a copy of the engineering image
`.work/winlogon-vm-20261118/image-01/XP25-Winlogon-Fix-8.2.qcow2`
(SHA-256 `fe633d1570f042b3cc8f869ad0fe1f6fabfc0e048ab57437b8d5c6e89f1ec173`).
From 2026-11-19 it ran the Milestone 8.4 Winlogon `289abb03…`
([update](#update-to-the-milestone-84-winlogon-2026-11-19)). **Since 2026-11-20
it runs the R-0 Winlogon `020eaf40…` and the R-1 `win32k.sys`, `user32.dll` and
`gdi32.dll`** ([redeploy](#redeploy-with-r-0-and-r-1-2026-11-20)).

## Redeploy with R-0 and R-1, 2026-11-20

The VM's own disk now carries four rebuilt files from `xp25-modernization`
`16062930d`:

| File | Before | After |
| --- | --- | --- |
| `winlogon.exe` | `289abb03…` (8.4) | `020eaf4047dfeae7ed7ebdab507d951766e715065917430c9d6bb41f600e0f2b`: screen savers and the idle lock ([R-0](winlogon-screen-saver.md)); build collection `.work/screensaver-20261119/wl-collect-02/files.json` |
| `win32k.sys` | `b28afb2f…` (1106) | `f698e04d02f041f767a9a22bfb52c640ff0e1c3373bd616f18e180fc50dae4dd`: four fixes ([R-1](source-built-component-assessment.md)); collection `.work/r1-20261119/collect-patched-02/collect.json` |
| `user32.dll` | `a51976dd…` (1106) | `4cccacd3aeefccdf691548cb83977cf1c5ec4e1a866b5617ca5871884ebcd9b4`: ANI parsing |
| `gdi32.dll` | `09698075…` (1106) | `13e538d3ad0fa34ff0a604528930644535333d0e59f7aee2671e12e56c13c0e5`: WMF `SETABORTPROC` |

`W2` is `.work/vm-redeploy-20261119` in `xp25-modernization`, and `V` is the VM
directory, `xp25-winlogon-ui/.work/virt-manager-XP25-Winlogon-Fix-20261118`.
`W2/update.py` journals every step:

1. You were logged on; the desktop had no open window. The VM was turned off
   through Start → Turn Off Computer → Turn Off. libvirt reported
   `Shutdown Finished after guest request` and `shut off (shutdown)`.
2. `update.py snapshot before`, then `update.py reference`: a frozen reflink
   copy of the VM disk, `a0cd32627d5d2bb49ab873d5c8ff4194d7b0ba59fa0c6af4fe27e662db425adb`.
   It hashed the same as the disk before and after the copy, and
   `qemu-img check` found no errors.
3. The new `build/package_image.py` (the multi-file form of
   `winlogon_package_image.py`) replaced the four files offline. It checks every
   installed copy against the expected hash first, and every replacement against
   its native build's collection record:

   ```sh
   S=.work/screensaver-20261119 P=.work/r1-20261119/collect-patched-02
   python3 build/package_image.py --parent W2/reference/XP25-Winlogon-Fix-vm-20261120.qcow2 \
     --parent-sha256 a0cd32627d5d2bb49ab873d5c8ff4194d7b0ba59fa0c6af4fe27e662db425adb \
     --replace /WINDOWS/system32/winlogon.exe=$S/winlogon-ss-02.exe,289abb03…,$S/wl-collect-02/files.json \
     --replace /WINDOWS/system32/win32k.sys=$P/binaries/win32k.sys,b28afb2f…,$P/collect.json \
     --replace /WINDOWS/system32/user32.dll=$P/binaries/user32.dll,a51976dd…,$P/collect.json \
     --replace /WINDOWS/system32/gdi32.dll=$P/binaries/gdi32.dll,09698075…,$P/collect.json \
     --name XP25-R0-R1.qcow2 --output W2/image-01
   ```

   (The full expected hashes are in `W2/image-01/manifest.json`.) The image is
   `XP25-R0-R1.qcow2`, `c51832288b286bce510edccc2666581fa4a14e1d64c71b25cdecbbe94d49e6b7`,
   and `qemu-img check` found no errors.
4. **Image verification** on disposable overlays of that exact image
   (one-vCPU KVM):
   - The two-account switch oracle **passed**: 9/9 switches painted, accounts
     alternating, wrong password refused (`W2/runs/image01-2acct-up-01`).
   - The screen-saver probe **passed** all 10 gates in `image01-ss-up-04`. The
     guest shut down normally, and the gates were decided from Winlogon's and the
     probe's serial records merged with their file logs. The serial-only verdict
     was also 10/10.
   - **Three earlier runs are kept as failed** (`failure.json` in each). In all
     three, Winlogon's own log shows the guest behaving correctly. The failures
     came from Winlogon lines lost from COM1, which it opens exclusively for each
     line (roadmap R-0b):
     - `image01-ss-up-01`: the harness missed an unlock record and retyped onto
       the unlocked desktop. That started Internet Explorer 8's setup, which held
       up the logoff.
     - `image01-ss-up-02`: one return-to-desktop line was lost while the probe
       wrote at the same moment.
     - `image01-ss-up-03`: a burst of lock-notification lines was lost.

     Fixes made in response:
     - The harness types only while the unlock dialog is on screen, and also
       counts MSGINA's unlock result as an unlock.
     - The probe waits 2 s after each transition before writing (`probe-02`,
       `d608f888…`).
     - The harness turns the guest off normally and decides gates from the merged
       records.
5. `update.py swap`: the VM disk still hashed `a0cd3262…`. It was kept beside
   the new one as `V/XP25-Winlogon-Fix.289abb03.qcow2`. A reflink copy of the
   image took its place, hashing `c5183228…` before the first boot.
   `update.py describe` replaced the domain description. `update.py compare`:
   the domain XML differs only in `<description>`, no other domain, network,
   filter or running QEMU process (XP25-AI) changed, and the kept disk and the
   reference are unchanged.
6. Observed in the VM (`virsh start`, then `vm/libvirt_ui.py` screenshots
   `W2/ui/10`–`13`):
   - boot to the painted logon dialog;
   - Enter (blank password) to the `XP25` desktop, where the Found New Hardware
     Wizard opened again and was cancelled;
   - Log Off, back to a painted dialog.

   The VM was left **running at the logon dialog**.

**What changes for you.** After ten idle minutes the logon screen shows the
Windows XP logo saver, and a session shows the user's saver. With "On resume,
password protect" set, the session locks when the saver ends. `C:\xp25\native-winlogon.log`
keeps its earlier history.

To go back, shut the VM down and rename `V/XP25-Winlogon-Fix.289abb03.qcow2` to
`V/XP25-Winlogon-Fix.qcow2`, after moving the current file away. That disk is
the VM's state before this redeploy, with the 8.4 Winlogon and the 1106 trio.
`V/XP25-Winlogon-Fix.f24bba5b.qcow2` is the state before 2026-11-19.

## Update to the Milestone 8.4 Winlogon, 2026-11-19

The VM's own disk, with the state it had when it was last shut down, now
carries the Milestone 8.4 Winlogon
`289abb032a63a0921bbf3a4c78d2603d80a2d2e6136e861cd32813c09e108312` (commit
`5c690eb4c`, native build `m84-wl-build-01`, collection
`.work/modernization-20261118/wl-collect-01/files.json`). That build has the
account-switch fix and also stops logging the screen-saver notice that USER
repeats twice a second while the station is idle
([Milestone 8.4](PROGRESS.md#current-checkpoint)). Under the previous Winlogon,
`C:\xp25\native-winlogon.log` had grown to 17,161,689 bytes (169,919 lines). Of
those, 169,280 were that notice: 84,640 notices at two lines each. The file was
left in place (read from the frozen reference with `vm/read_guest.py`).

Paths below are relative to the `xp25-modernization` worktree. `V` is the VM
directory, `xp25-winlogon-ui/.work/virt-manager-XP25-Winlogon-Fix-20261118`.
`.work/winlogon-vm-20261119/update.py` journals every step to `commands.jsonl`:

1. `update.py snapshot before`: every domain, network and filter definition,
   and the running QEMU processes. The domain was `shut off (shutdown)`, a guest
   shutdown.
2. `update.py reference`: a frozen reflink copy of the VM disk,
   `reference/XP25-Winlogon-Fix-vm-20261119.qcow2` (mode 0444,
   `355d8091153fa4156ab526b2ba774b5c5c8f389994f0e9098ceadc9adb590a75`). The VM
   disk hashed the same before and after the copy, and `qemu-img check` found no errors.
3. `build/winlogon_package_image.py` replaced `winlogon.exe` offline:

   ```sh
   W=.work/winlogon-vm-20261119 M=.work/modernization-20261118
   python3 build/winlogon_package_image.py --parent $W/reference/XP25-Winlogon-Fix-vm-20261119.qcow2 \
     --parent-sha256 355d8091153fa4156ab526b2ba774b5c5c8f389994f0e9098ceadc9adb590a75 \
     --expect-installed f24bba5b2561b183a33d1cda106941138c28b1cc8dc50fde79f23f4511f733d3 \
     --winlogon $M/winlogon-m84-01.exe --collect $M/wl-collect-01/files.json \
     --name XP25-Winlogon-M84.qcow2 --output $W/image-01
   ```

   The installed file was the expected `f24bba5b…`. The result
   `image-01/XP25-Winlogon-M84.qcow2` hashes
   `471e1b068070915fbb334b77ef0ec307e3ff114ec81d1cc22f6deb74daf8d95a`, and
   `qemu-img check` found no errors.
4. **Image verification.** The two-account oracle ran on that exact image (one-vCPU KVM,
   nothing staged, disposable overlay):

   ```sh
   python3 vm/winlogon_switch_probe.py --name image01-2acct-up-01 --image $W/image-01/XP25-Winlogon-M84.qcow2 \
     --image-sha256 471e1b068070915fbb334b77ef0ec307e3ff114ec81d1cc22f6deb74daf8d95a \
     --probe $M/security-probe-01/security_probe.exe --second-user XP25B --second-password sw1tch25 \
     --wrong-password-cycle 3 --cycles 10 --out-root $W/runs
   ```

   **Passed**: 9/9 switches painted, the accounts alternated and the wrong
   password was refused (`$W/runs/image01-2acct-up-01`).
5. `update.py swap`: the VM disk still hashed `355d8091…`. It was renamed to
   `V/XP25-Winlogon-Fix.f24bba5b.qcow2` and kept. A reflink copy of the image
   took its place as `V/XP25-Winlogon-Fix.qcow2`, which hashed `471e1b06…`
   before the first boot.
6. `update.py describe` replaced the domain `<description>`. Then
   `update.py snapshot after` and `update.py compare` ran: the domain XML
   differs only in `<description>`, and no other domain, network, filter or
   running QEMU process (XP25-AI) changed. The kept disk and the reference are
   unchanged (`preservation.json`).

**Observed in the VM** (`virsh start`, then `vm/libvirt_ui.py` send-key and
screenshots `$W/ui/01`–`08`):

* The painted logon dialog came up with `XP25` filled in.
* Enter with the blank password reached the `XP25` desktop. The Found New
  Hardware Wizard opened again and was cancelled.
* Start → Log Off → Log Off brought back a painted dialog.
* A second logon and logoff brought back a painted dialog again.

The VM was left **running at the logon dialog**. MP, TCG and the lifecycle
gates for this binary are the Milestone 8.4 overlay runs on the 8.2 image. They
were not repeated on this disk.

To return to the previous Winlogon, shut the VM down and rename the files
back: `V/XP25-Winlogon-Fix.qcow2` (now `471e1b06…` plus whatever the VM has
written since) out of the way, then `V/XP25-Winlogon-Fix.f24bba5b.qcow2` back to
`V/XP25-Winlogon-Fix.qcow2`.

## The image (2026-11-18)

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

## The VM (2026-11-18)

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

To reset the VM to a packaged image, shut it down, then replace the copy. The
2026-11-19 image (the VM's disk as of that day, with the 8.4 Winlogon) is
`xp25-modernization/.work/winlogon-vm-20261119/image-01/XP25-Winlogon-M84.qcow2`.
The clean 2026-11-18 image (first boot, Winlogon `f24bba5b…`) is used below,
with paths relative to the `xp25-winlogon-ui` worktree:

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
| Disk | `XP25-Winlogon-Fix.qcow2` (IDE `hda`, writeback), a standalone reflink copy. It hashed equal to its image before its first boot (`fe633d15…` on 2026-11-18, `471e1b06…` on 2026-11-19) |
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
