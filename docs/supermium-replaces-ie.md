# Supermium replaces Internet Explorer (2026-11-21)

The XP25-Winlogon-Fix VM now has Supermium as its only web browser, and Internet
Explorer is removed from it: the browser, its HTML engine (MSHTML) and the
JScript and VBScript engines are deleted, not hidden. Evidence root:
`.work/supermium-vm-20261120/` in `xp25-modernization` (`W` below).

This builds on Milestone 7 (`browser-modernization.md`, `browser-offline-7a.md`,
`browser-security-7b.md`), which installed Supermium but only hid IE.

## What is removed, kept and replaced

**Deleted** (`build/ie_removal.py`), each from `system32`, its `en-US` language
files and the Windows File Protection copies in `dllcache`:

| Part | Files |
| --- | --- |
| IE8 browser | everything in `Program Files\Internet Explorer` except `ieproxy.dll` (`iexplore.exe`, the developer tools, the Connection Wizard, …) |
| HTML engine | `mshtml.dll`, `mshtmled.dll`, `mshtmler.dll`, `mshtml.tlb`, `iepeers.dll` |
| Script engines | `jscript.dll`, `vbscript.dll`, `jsproxy.dll` (proxy scripts) |
| HTML applications | `mshta.exe` |
| IE settings and setup | `inetcpl.cpl` (Internet Options), `ie4uinit.exe`, `ieudinit.exe`, `BrowserChoice.exe` |

Before the files go, their COM registrations are removed the way their own
unregistration would (`browserctl unregister-file`): 46 classes and 3 type
libraries, the same count as the image's registry lists for those servers.
Also removed: IE's App Path and Start-menu client, its three Active Setup
entries (so new accounts get no IE setup), and the open verbs of `.hta`, `.mht`,
`ftp://` and the MSHTML print verbs of `.htm`/`.html`.

**Kept**, because Windows itself needs them. Explorer imports or loads WinINet,
URLMon, Shdocvw, BrowseUI, IEFrame and IERtUtil; `ieproxy.dll` is the proxy/stub
of 270 COM interfaces, Explorer's own among them (taskbar bands, travel log,
notifications). The full list with reasons is `KEPT` in `build/ie_removal.py`.
WinINet and URLMon are networking and download libraries: they do not render
HTML or run scripts, and they stay as patched as the image's other 2013 IE files.

**Replaced** (what used the deleted engine):

| Was | Now |
| --- | --- |
| Web links, `.htm`, `.html`, `.url`, Start-menu Internet | Supermium 150.0.7871.255 R2.01, through `XP25Browser.exe` (SAFER Normal User token, job object) |
| Help and Support (Start menu) | XP25 Help (`components/help`), the Explorer string that starts it changed (`build/prepare_native_help.py`) |
| User Accounts panel (`nusrmgr.cpl`, an HTML application) | `xp25users.cpl` (`components/browser/xp25_users.c`), which opens the classic User Accounts dialog (`netplwiz`, as `control userpasswords2`) |
| Search Companion (HTML) | Explorer's classic search pane |

**No longer works** (its engine is gone): Help and Support pages, HTML Help
(`.chm` files), `.hta` applications, `.js` and `.vbs` scripts, HTML mail in
Outlook Express, the Network Setup Wizard, Active Desktop web content.

**Internet.** Supermium's machine policy sends every request through the host's
browser gateway at `10.25.0.1:3128` and forces HTTPS-only mode. The gateway
(`vm/browser_gateway.py --allow-any-public`) tunnels HTTPS to any public name and
refuses literal IP addresses, names that resolve to a private, loopback,
link-local or metadata address, other ports and plain HTTP. It accepts only the
VM's reserved address, and it does not log the names visited. The VM's NIC
filter (`xp25-browser-gateway`) admits only DHCP, DNS, ICMP, the AI gateway and
this port.

**Limits.** Supermium has no renderer sandbox on NT 5.1; XP25Browser runs it
with a reduced token in a job object (Milestone 7B). The intermittent
`chrome.dll` `0x842214` handle CHECK from Milestone 7 is not fixed. System
Restore is on, so restore points taken before this change may hold copies of the
deleted files, and restoring to one of them would bring IE back.
`AllowProtectedRenames` stays set to 1 after the removal, as hotfix installers
leave it: a later boot-time rename queued by an administrator may also replace a
protected file. The gateway carries HTTPS only, so plain-HTTP requests that
Supermium sends through it (some update and certificate-revocation fetches) are
refused. The gateway is a user service of the host account (`systemctl --user`,
lingering off): it runs while that account has a session, and the browser in the
VM reaches nothing without it. It runs `vm/browser_gateway.py` from the
`xp25-modernization` worktree, which must stay in place.

## How the image was made

All commands are from `xp25-modernization`; every output directory is new.

1. **Inputs.** The VM was shut off (by you). Its disk was copied, frozen 0444:
   `W/reference/XP25-Winlogon-Fix-vm-20261120b.qcow2`, `6dbd3f88…00f6`.
   Supermium `supermium_150_32_nonsetup.zip` was downloaded again and matched the
   pin in `components/browser/release.json` (`d9a06a6c…43b3`, 165,223,567 bytes).
2. **Native build** of the 14 tools and 2 DLLs with the original NT compiler, in
   an overlay of the AI image `ec22f45b…`: `build/prepare_browser_native.py`,
   `vm/browser_lab.py`, `build/collect_browser_native.py` (`W/native-03-collect`).
   Builds 01, 02 and 04 differ from it only in the test-only shell probe, after
   `build/compare_pe.py` normalization (the NT linker stamps time and debug IDs).
   Build 04 (`W/native-04-collect`, `browser_shell.exe` `d109b03d…`) is the shell
   probe of the regression media: it checks the Start-menu client `XP25Browser.exe`
   and either Internet policy (blocklist, or gateway proxy with HTTPS-only). The
   guest probes `ieremoval_probe` and `msibuild_probe` are MinGW builds
   (`build/guest.py`).
3. **Media.** `build/prepare_browser.py --software-rendering --internet gateway`,
   `build/prepare_native_help.py` (Explorer `487830…` → `e41a66db…`, string 732
   only) and `build/prepare_vm_browser.py`, which adds the applet, the removal and
   two Startup suites (`W/vm-media-04`).
4. **Install run** (`vm-install-04`): an overlay of the reference with the patched
   Explorer staged offline (replaced only if the installed one is `487830…`). The
   XP25 account logs on (`vm/browser_wait_shutdown.py --xp25-logon`); the suite
   installs Supermium, XP25 Help and the applet, unregisters the removed servers,
   sets `AllowProtectedRenames` and queues every removed file for deletion at the
   next boot. The guest is turned off from the Start menu (`--ui-shutdown`):
   `shutdown.exe` has no InitShutdown server under the XP25 Winlogon.
5. **Verify run** (`vm-verify-04`): an overlay of the install run. Its boot is the
   one in which the Session Manager deletes the files; the suite then runs
   `ieremoval_probe`, the XP25 Help self-test and a `.js` file that must not run.
6. **Image** (`vm/package_vm_browser_image.py`): checks both runs, every installed
   file against the media, the patched Explorer and that every removed file is gone,
   then flattens the verify run into a standalone image:

   ```sh
   python3 vm/package_vm_browser_image.py --install-run W/runs/vm-install-04 --verify-run W/runs/vm-verify-04 \
     --media W/vm-media-04 --name XP25-Supermium-NoIE.qcow2 --output W/image-02
   ```

   `W/image-02/XP25-Supermium-NoIE.qcow2`,
   `9e1e8f081b3ffc113aa4bf9f20e9b82097c681952c271b05fbf7a9e8f3e5b84d`, no backing
   file; `qemu-img check` found no errors and `qemu-img compare` found it equal to
   the verify run's disk. 295 installed files match the media, all 36 removed files
   are absent, `Program Files\Internet Explorer` holds only `ieproxy.dll`. Verify
   markers: removal probe 0, Help self-test 0, the `.js` file exited 1 (no engine).

## Tests of the image

Disposable overlays of `image-02`, one-vCPU KVM (the VM's own profile), two
guests at a time; `W/run-tests.sh` and `W/run-tests-2.sh`. Host: the full suite,
156 tests OK (12 skipped).

| Test | Run | Result |
| --- | --- | --- |
| Browser regression through a host gateway that admits any public HTTPS name (`vm/browser_matrix.py --xp25-logon --internet gateway`, media `W/test-media-04`, `597527672cb8…e011`) | `img02-browser2-up` | **23/26 checks.** Shell probe 15/15; ShellExecute of http, https, `.html`, `.htm` and `.url` returned 0 and the four rendered receipts pass; a `.url` to `javascript:` refused (87); DevTools 11/11 (modern JavaScript, local HTML, tabs, a valid certificate loads and expired, wrong-host and untrusted ones are refused, download, appearance setting), `https://www.wikipedia.org/` (on no list) loaded over TLS 1.3 through the gateway and `https://169.254.169.254/` not loaded (`ERR_ADDRESS_UNREACHABLE`: Chromium sends link-local addresses directly, and the guest has no route); profile and settings persist across a restart; compatibility suite; MSI built natively, installed and removed; AI 55/0 and provider 7/0; turned off from the Start menu. The three false checks: Remote Registry is disabled by the image's security baseline (5 `regsvc` cases, error 1058), counted twice; and the four probe cases that have been `not_tested` since Milestone 7. Gateway `W/gw-02`: 42 tunnels to 20 names, 13 non-CONNECT requests refused |
| Security lab `proof` (`--regression-iso` with the native MSI build) | `img02-proof-up-01` | **34/35.** The failure, `audit_finds_no_high_severity_issue`, lists four driver services added since the baseline: `HidUsb`, `mouhid`, `usbhub`, `usbuhci` |
| Control: `proof` on the unchanged reference disk | `ref-proof-up-01` | 34/35, the **same** failure with the same four drivers. They come from the VM's USB tablet in virt-manager: the reference disk's SYSTEM hive and `drivers` folder have them, the 8.2 image has neither |
| Screen-saver probe, 10 gates | `img02-ss-up-01` | **Pass**, 10/10 |
| Two-account switch oracle | `img02-2acct-up-02` | **Pass**, 9/9 painted, accounts alternate, wrong password refused |

Not tested on this image: two-vCPU and TCG (the VM runs the uniprocessor HAL on
one vCPU), the `firewall`, `standard-user` and `ai-repeat` roles, the Winlogon
lifecycle harness, and pages other than those named above.

## In the VM, 2026-11-21

`W/update.py` journals every step to `W/commands.jsonl`.

1. The VM was shut off (since 2026-11-20). `update.py snapshot before`.
2. `components/browser/host/install-browser-gateway.sh`: a DHCP reservation
   `52:54:00:25:00:07` → `10.25.0.26` in `XP25-Isolated` (no lease held it), the NIC
   filter `xp25-browser-gateway`, and the user service `xp25-browser-gateway`:
   `vm/browser_gateway.py --listen 10.25.0.1:3128 --client 10.25.0.26
   --allow-any-public --idle 300 --no-allow-log`, log
   `~/.local/state/xp25/browser-gateway.jsonl`.
3. `update.py swap`: the VM disk still hashed `6dbd3f88…00f6`, the reference.
   It is kept as `XP25-Winlogon-Fix.ie8.qcow2`; a reflink copy of `image-02` took
   its place and hashed `9e1e8f08…b84d` before the first boot.
4. `update.py configure`: memory 512 MiB → 1 GiB, filter `xp25-gateway-only` →
   `xp25-browser-gateway` (same parameters plus `BROWSER_PORT` 3128), description.
5. `update.py snapshot after` and `compare`: `preserved: true`. The domain
   differs only in memory, filter and description; `XP25-Isolated` only by the
   one DHCP host; the only new filter is `xp25-browser-gateway`; no other domain,
   network or filter changed; XP25-AI kept its PID, start time and command; the
   kept disk and the reference are unchanged.
6. Observed by screenshot (`W/ui/10`–`16`): `virsh start`; the guest leased
   `10.25.0.26`; a painted logon dialog; Enter (blank password) to the desktop,
   where the Found New Hardware Wizard opened again; the Start menu's Internet
   entry is **Supermium**; Run → `https://www.wikipedia.org/` opened the page in
   Supermium through the gateway; Run → `iexplore`: "Windows cannot find
   'iexplore'"; Log Off back to a painted dialog. The VM was left **running at
   the logon dialog**.

## Failures kept

- `vm-install-01` (superseded): its suite ended with `shutdown.exe`, which does
  nothing under the XP25 Winlogon; the guest was turned off from the Start menu
  after its screen saver had started. The suites no longer call `shutdown.exe`.
- `vm-verify-02` (failed, `failure.json`): two defects that the probe found.
  1. Every file Windows File Protection protects survived, byte-identical, while
     the unprotected ones (the `dllcache` copies, language files and IE8-only files)
     were deleted. The Session Manager skips protected files unless
     `AllowProtectedRenames` is set, as hotfix installers do; the removal now sets it.
  2. Explorer had registered the web-link handler, then the console tool
     `browserctl.exe`, as a "legacy" Start-menu Internet client and made it the
     machine default; its command opened nothing. Web links now open through
     `XP25Browser.exe`, the Supermium client's own program.
- `vm-verify-03` (failed, `failure.json`): every removed file was gone, but
  Explorer still registered `XP25Browser.exe` as a legacy client: it looks a
  client up by the key named after the handler's program file, and the Supermium
  client's key was named `Supermium`. The key is now `XP25Browser.exe` (shown as
  Supermium). `vm-install-02` and `-03` are kept as superseded.
- `image-01` (interrupted, `failure.json`): the session that packaged it ended
  during `qemu-img compare`, before the manifest. `image-02` is the same command
  into a fresh directory.
- `img02-browser-up` (failed, `failure.json`): the suite had been written for the
  unhardened AI image. On this image Supermium could not use the DevTools test
  profile `C:\xp25\browser\TestProfile` (the folder is administrators-only there,
  and the browser runs with the SAFER Normal User token), and Windows Firewall
  blocked the test bridge, so DevTools never answered. Its shell probe (build 02)
  also still expected the client key `Supermium` and the blocklist policy.
  The ShellExecute cases passed and rendered. Fixed in the test media only: the
  suite gives the logged-on user `C:\xp25\browser` and opens port 9223 to
  `10.25.0.1`, and build 04's shell probe checks either policy.
- `img02-2acct-up-01` (failed, `failure.json`): 8/9. In cycle 2 the oracle saw a
  beige MSGINA body, waited 3 s and captured the black gap before the logon
  dialog; 4 s later the dialog was there and painted. Winlogon's records show a
  normal logoff and logon. The oracle takes any MSGINA body for the logon dialog;
  a native build was running beside two test guests at the time. The rerun
  passed 9/9.
