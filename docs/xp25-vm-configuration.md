# XP25-Winlogon and XP25-AI configuration (2026-10-25)

This record covers the second configuration pass on the two interactive libvirt
VMs, XP25-Winlogon and XP25-AI. It continues
[xp25-winlogon-oem-branding.md](xp25-winlogon-oem-branding.md) and
[virt-manager-xp25-ai.md](virt-manager-xp25-ai.md).

**Result:** both VMs boot and run at the same time on the isolated network. Each
has its own MAC address, DHCP lease and Windows computer name. Each System
Properties dialog shows **QuoolAI** and the full model **Windows XP 25th
Anniversary Edition**. All 16 gates pass on each VM, decided from the guest's
own records, which were read offline after a guest-requested shutdown. Both VMs
are left running with System Properties open.

| | XP25-Winlogon | XP25-AI |
| --- | --- | --- |
| MAC / DHCP lease | `52:54:00:25:00:04` / `10.25.0.12` | `52:54:00:25:00:05` / `10.25.0.13` |
| Computer name (NetBIOS and DNS) | `XP25-WINLOGON` (was `XP25-BASELINE`) | `XP25-AI` (was `XP25-BASELINE`) |
| `OEMINFO.INI` | QuoolAI (from the first pass) | QuoolAI (new, `7760193a…e5fc`) |
| `sysdm.cpl` | widened, `98f3c968…ff03` | widened, `98f3c968…ff03` |
| Help and Support OEM copy | QuoolAI | QuoolAI (new) |
| Winlogon | independent XP25 Winlogon | original Winlogon |

## 1. System Properties: widened Computer lines

The General page's Computer lines (`IDC_GEN_MACHINE_*`, controls 63–68 and
70–72) are `Link Window` controls at x=141, 110 DLU wide. That is 165 px at
96 DPI, and "Windows XP 25th Anniversary Edition" needs 179 px in Tahoma 8 pt.
They end 5 DLU before the right edge of the 256-DLU page, so there was no room
to widen them in place.

`build/prepare_branding.py` now, as part of the reviewed `sysdm.cpl` step
(`brand_system_properties`):
- widens those nine lines to **124 DLU** (186 px);
- widens the page by the same 14 DLU, to **270 DLU**, so the original right margin is kept;
- moves no control.

The step refuses any other original geometry. Nothing else in the pack changes:
- the new package's `xpsp1res.dll`, `winver.exe`, `explorer.exe`,
  `shell32.dll` and `logonui.exe` are byte-identical to the verified
  `patched-ui-06` package;
- `sysdm.cpl` differs from the previously installed branded file
  (`796dd0dd…cb89`) only in resource `(5, 101, 1033)`. `verify_pair` confirms that
  sections, imports, exports and VERSIONINFO are unchanged.

The original is still `99bd5757…8067`, and WFP's cache still holds that unbranded
copy. As with the first branding, the file is written offline and its retention
is checked after a boot.

`build/install_branding_overlay.py --upgrade-from PREVIOUS_PACKAGE` installs the
change into an overlay whose base already carries the previous package. It
requires the base file to equal the previous package's hash, skips components
that did not change, and backs up the previous file to `/xp25/brand-<sha12>-<name>`.

The `oem` probe now also checks the layout and DPI fit (18 of its 19 cases
touch System Properties or text fit). It measures every single-line General
page text against its control and requires that no text line overlaps another.
It visits all seven tabs and requires each page to exist with every visible
control that shows something inside it. Empty text lines are skipped, because
Microsoft's template already places the spare line 72 below the page. It
requires the sheet's width to fit the screen; its height (486 px) already
exceeds 640×480 with the original template, so it is only recorded. Finally it
checks the model against 124 DLU at 96, 120 and 144 DPI:

| DPI | Model text | 124 DLU line | old 110 DLU line |
| --- | --- | --- | --- |
| 96 | 179 px | 186 px | 165 px |
| 120 | 213 px | 217 px | 193 px |
| 144 | 267 px | 279 px | 248 px |

The DPI rows are font measurements in the guest; neither VM was switched to another
DPI. Screenshots of all seven tabs (`rehearsal-ai-01/09-tabs-montage.png`) show the
other pages unchanged, with extra space on the right.

## 2. OEM branding on XP25-AI

XP25-AI received the same change as XP25-Winlogon:
- `OEMINFO.INI` with exactly the content of `branding/oeminfo.ini`, which is the
  file on XP25-Winlogon;
- Help and Support's `HelpSvc\OEMInfo` copy set with `reg.exe`;
- the widened `sysdm.cpl`.

Its `OEMINFO.INI` had been the third-party file (`a1052310…eaee`), and
there was no OEM logo. Backups:

- In the guest, `C:\xp25\vmconfig-20261025\backup\` (made by `vm-before.cmd`):
  - `OEMINFO.INI.before`;
  - `reg export` copies of `HelpSvc\OEMInfo`, `ComputerName` and `Tcpip\Parameters`;
  - `computername.before.txt`;
  - `restore.cmd`, and the `oem_probe.exe` it uses for renaming.
- In the guest, from the offline writer: `C:\xp25\oeminfo-a10523107276.ini` and
  `C:\xp25\brand-796dd0dd8bac-sysdm.cpl`.
- On the host, `.work/vm-config-20261025/XP25-AI/offline/previous-*`.

XP25-Winlogon got the same `vmconfig` backups, plus `C:\xp25\brand-796dd0dd8bac-sysdm.cpl`.
Its first-pass backups in `C:\xp25\oem-backup-20261025\` remain.

## 3. Why XP25-AI had no IP address

`XP25-Isolated` has a DHCP range of the single address `10.25.0.10`, plus host
reservations `.10`–`.13`. dnsmasq offered `10.25.0.13` to XP25-AI, then NAKed
every request with **"no leases left"** (496 NAKs logged) while XP25-Winlogon held
`10.25.0.12`. The network's dnsmasq had started on 2026-10-23, when two
reservations already existed, and it still refused a second concurrent lease.
So its lease limit is the size of the dynamic range (one address), and the
reservations do not add to it. dnsmasq's configuration file is root-only, so the
limit itself was inferred from this behaviour, not read.

The guest's `ipconfig /renew` "Access is denied" came from those NAKs:
`net localgroup administrators` in the guest lists `XP25`.

The fix is one live and persistent update:
`virsh net-update XP25-Isolated add ip-dhcp-range "<range start='10.25.0.20' end='10.25.0.29'/>" --live --config`.
- libvirt restarted only this network's dnsmasq.
- XP25-Winlogon's lease survived the restart.
- XP25-AI received `10.25.0.13` on its own, without restarting.

Nothing else in either network changed. No VM was restarted, and every domain
definition and state was unchanged by the update.

## 4. Unique computer names

`vm-before.cmd NAME` renames the computer with `oem_probe.exe --rename`, which
calls `SetComputerNameExA(ComputerNamePhysicalDnsHostname)` and so sets the
NetBIOS and DNS names together. The new name takes effect at the next start.

Two problems were found on the way:
- **WMI rename fails on the XP25-Winlogon image.** `wmic computersystem ... call
  rename` fails there with `0x80041004` (provider failure); it returned 0 on the
  AI image. The native call works on both.
- **Independent Winlogon gap.** The original `winlogon.exe` contains the strings
  `NV Hostname`, `Hostname`, `NV Domain` and `Tcpip\Parameters`, and copies the
  pending DNS host name into the active one at startup. The independent XP25
  Winlogon does not. After a rename it left `Hostname=xp25-baseline`, and the
  Computer Name tab showed a perpetual pending-rename notice (control 1019,
  drawn outside its page). `vm-before.cmd` therefore also sets the active
  `Tcpip\Parameters\Hostname` itself. The Winlogon was not changed.

After the rename, the independent Winlogon on the Winlogon rehearsal disk still
recorded all of these on COM1:
- `profile_hive_identity_verified`;
- `licensing_policy_verified` and `licensing_policy_allowed`;
- `explorer_token_identity_verified`;
- `session_interactive`.

## 5–6. Isolation and preservation

- `XP25-Isolated` has no `<forward>`, and its only change is the added range.
  The `default` network and the host's routes are unchanged. The bridge's
  only ports are the two VM taps.
- The guests have no default gateway, `ping 192.0.2.1` fails (exit 1), and
  DHCP still sends no router option.
- Every domain definition is byte-identical before and after. That covers
  xp25-sp3, XP25-Winlogon, XP25-AI, XP25-Anniversary and the other
  registered domains. The running `xp25-sp3` has the same PID and start time.
- Frozen images: image-05 (`ec22f45b…be2a`), engineering-image-02
  (`0df7fc05…c51c`) and the AI reference base (`39112bbd…0296`) hash
  unchanged and are still read-only (0444). XP25-AI's writes went only to its
  overlay.
- Activation data matches each VM's frozen source image: `wpa.dbl`,
  `WPAEvents\OOBETimer`, `ProductId` and `DigitalProductId`.
- The 22 XP25 Winlogon components still match the XP25-Winlogon registration
  record. The five AI binaries in `C:\Program Files\XP25` still match image-05.
  The offline step checked that they, the branding and licensing files, and
  WFP's `sysdm.cpl` were unchanged.

## 7. Procedure and verification

All tools are committed:
- `tests/guest/oem_probe.c` and `tests/guest/vmconfig/*.cmd`, packed by
  `build/prepare_vm_config_media.py`;
- `vm/vm_offline_update.py` (offline writes and `--rollback`);
- `vm/vm_config_results.py` (gates);
- `vm/libvirt_ui.py` (libvirt API input only, with no monitor commands);
- `vm/regf.py`.

Every write needs a guest-requested shutdown first, confirmed by libvirt's
`Shutdown Finished after guest request` event.

1. **Rehearsals** on disposable overlays, with the same KVM profile, COM1 and no NIC:
   - `rehearsal-ai-01` (image-05): the full flow passed, then `--rollback`
     restored both files.
   - `rehearsal-wl-01` (engineering-image-02) found the WMI, hostname and
     Computer Name tab problems above. It also had one **unexplained restart**:
     seconds after the probe finished on boot 2, Windows restarted. QEMU saw no
     reset and no panic, no clean-stop event was logged, and no dump was saved
     (small dumps are enabled). It did not recur in six later System
     Properties probe runs on that disk (two inside `vm-verify.cmd`) across two
     boots, with automatic restart turned off. That disk is
     kept with `failure.json`.
   - `rehearsal-wl-02` repeated the final flow on a fresh overlay; every gate passed.
2. **Each VM:** start (or use the running VM), insert `vmconfig.iso` live, log on,
   then `D:\vm-before.cmd NAME`, then Turn Off, then
   `vm_offline_update.py --domain`. XP25-AI got `sysdm.cpl` and `OEMINFO.INI`;
   XP25-Winlogon got `sysdm.cpl` only. All nine checks passed on each.
3. **Together:** start both, then `D:\vm-verify.cmd PEER-IP` in each while both
   run, then Turn Off both, then `vm_config_results.py --ip --peer-name`.
   - Host side: `ping` from `10.25.0.1` reached both, and the bridge's neighbour
     table shows both MAC/IP pairs.
   - Guest side: each `ipconfig` shows its own MAC and IP and no gateway. Each
     pinged the other and `xp25.test`. Each `nbtstat -A` shows the peer's distinct
     `<00> UNIQUE` name. All 19 probe cases passed.
   - Offline: the files and HelpSvc values were retained after the boot, the
     SYSTEM hive names are right, and the activation data is unchanged.
4. **Hand-off:** plain `virsh start` of both, logon, and Win+Pause in each. Both
   are left running. Their leases renewed on `.12` and `.13`.

```bash
python3 build/prepare_branding.py --inputs .work/branding-20261023/ui-inputs/WINDOWS \
  --config branding/en-US.json --output .work/oem-sysdm-20261025/brand-package-01
python3 build/guest.py --toolchain .work/toolchains/mingw-binutils/usr/bin --probe oem \
  --output .work/oem-sysdm-20261025/probe-04
python3 build/prepare_vm_config_media.py --probe .work/oem-sysdm-20261025/probe-04 \
  --output .work/oem-sysdm-20261025/media-04
python3 vm/vm_offline_update.py --domain XP25-AI --output .work/vm-config-20261025/XP25-AI/offline \
  --branding .work/oem-sysdm-20261025/brand-package-01 --upgrade-from PREVIOUS_PACKAGE \
  --oeminfo branding/oeminfo.ini --oeminfo-current a10523107276a62b093008bffbda9e44ba0f0e2cd3e08b2c85f0344d424aeaee \
  --require-guest ... --preserve-record .work/vm-config-20261025/ai-component-record.json
python3 vm/vm_config_results.py --domain XP25-AI --output ... --name XP25-AI \
  --sysdm 98f3c96802b157cf5b859b614f0b9e60b55bda1ee69b89fb3f3db7ea802fff03 \
  --oeminfo 7760193a85f4a23f78d61a9367ffc6f2bd21c81b9f593feb02fc6999b3dfe5fc \
  --baseline .work/ai-20261025/image-05/XP25-AI-Engineering.qcow2 --ip 10.25.0.13 --peer-name XP25-WINLOGON
```

`PREVIOUS_PACKAGE` is the main checkout's `.work/branding-20261023/patched-ui-06`. The
probe is `69078116…7647` (source `54bd294a…a05b`), and the media ISO is
`19d41a24…da71`.

## Undo

- **`sysdm.cpl` and `OEMINFO.INI`:** with the VM shut off, run
  `vm/vm_offline_update.py --domain NAME --output NEW --rollback <offline/result.json>`.
  This writes back the host backups after checking the current files are that
  run's output. It was tested on `rehearsal-ai-01`.
- **Name and Help and Support:** run `C:\xp25\vmconfig-20261025\backup\restore.cmd`
  in the guest as an administrator, then restart. It restores the previous OEM
  file, the HelpSvc values and the computer name. The rename half uses the
  probe copy next to it.
- **DHCP range:**
  `virsh net-update XP25-Isolated delete ip-dhcp-range "<range start='10.25.0.20' end='10.25.0.29'/>" --live --config`.
  After that, only one of the VMs can hold a lease again.

## Limits

- Evidence levels:
  - Guest records read offline decide every gate.
  - The rehearsals' COM1 is readable; the libvirt VMs' COM1 files are root-only.
  - Screenshots are visual evidence only.
  - The hand-off boot has screenshots only.
- The rehearsal-wl-01 restart remains unexplained. No such restart occurred on
  the real VMs during this work.
- `C:\WINDOWS\repair\software` still holds the old HelpSvc values on both VMs
  (Setup's repair hive). The old third-party bytes may also remain in free hive cells
  and unallocated clusters.
- Both VMs share a machine SID inherited from their images; only the names were
  made unique.
- XP25-AI's disk was hashed while the VM was running (it had been started
  outside this work), so that hash is not a consistent snapshot. XP25-Winlogon's
  disk hash before the change, while shut off, was `243ef564…8345`.
