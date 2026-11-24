# Compatibility matrix

The source-kernel desktop milestone passes in the recorded KVM clone, including
authentication, Explorer/Luna, file/application checks and normal shutdown.
`Not tested` means no installation, execution or
stability evidence exists; it is not a prediction of compatibility. Guest runtime
and hardware support must cite an image hash, exact version, environment and logs.

## MerlinAI repairs XP25 components, 2026-11-24

| Test | Recorded result |
| --- | --- |
| FltMgr (SP3 `fltmgr.sys`) on image-04 with the candidate kernel (one export added) | Loads: `sc query FltMgr` STOPPED → RUNNING under KVM UP, two-vCPU KVM (candidate MP kernel) and TCG; boot, logon, desktop, checks, MerlinAI status and turn-off pass in each |
| Kernel control relink in the builder's build VM | Reproduces the installed UP `b9531947…` and MP `42662074…` kernels exactly (link stamps aside) |
| Control builds of today's source vs image-04 | Winlogon, XP25Sec, XP25Audit and 5 of 6 MerlinAI files reproduced; the AI binaries are not |
| HTTP (`http.sys`), Server (`srv.sys`) | Still fail to load: push-lock (FASTCALL) and `RtlIpv4AddressToStringExW` exports missing; not repaired |
| Builder job from the VM (`J-20261124-103813-56bc78`) | ready, `fixed_verified` (gpt-4.1 investigation; nested tests under UP, two-vCPU and TCG pass; provenance as above). Not applied: that is the user's decision |

[Record](merlinai-whole-os.md).

## MerlinAI on the XP25-Winlogon-Fix VM; native build 12, 2026-11-23

| Test | Recorded result |
| --- | --- |
| XP25-Winlogon-Fix (virt-manager, KVM, 1 vCPU, 1 GiB), image-04 `378e9edd…8183`, MerlinAI build 10 | Enrolled; two authenticated health reports (one 11 s after boot, before logon); Control Panel shows MerlinAI, no Security Center, no Automatic Updates; builder reachable through the relay (authenticated job list); normal guest-requested turn-off. No update built, applied or rolled back on it |
| Image-04 switch oracle, first run `wf-2acct-up-04` | **Failed**, 3/5 painted (a Found New Hardware wizard took the keys); repetition `wf-2acct-up-05` 9/9 |
| Build 11, 9A suite | UP 24/24; TCG **failed** 20/24 (crash dialog refused the foreground) |
| Build 12, 9A suite (M9 baseline overlays) | UP 24/24, two-vCPU KVM 24/24, TCG 24/24; the crash dialog reports `foreground=1` |

The VM keeps build 10, whose crash dialog can come up without keyboard focus.
[Deployment](merlinai-milestone9.md#deployment-to-the-xp25-winlogon-fix-vm-2026-11-2223),
[build 12](merlin-dialog-readiness.md).

## MerlinAI continuation, 2026-11-22/23

Frozen build-10 image-04 (`378e9edd…8183`), under
`xp25-merlin/.work/merlin-vm-20261122/`. These results supersede the earlier
unpackaged-client and no-model limitations for this specific lab baseline.

| Test | Recorded result |
| --- | --- |
| Boot, logon, desktop, checks, MerlinAI status and normal turn-off | 6/6 under KVM UP, two-vCPU KVM and TCG (`wf-image04-*`) |
| Screen saver; account-switch painting | 10/10; 9/9 switches (KVM UP) |
| Security proof | 34/35; only the four inherited USB-driver audit findings fail |
| Browser gateway regression (KVM UP) | 23/26 aggregate; DevTools 11/11, persistence, MSI and AI 55/0 + 7/0 pass; disabled Remote Registry and explicit untested cases prevent a full pass |
| Model investigation, baseline `xp25wf4`, `J-20261123-020135-92f5c3` | Ready; controlled defect reproduced before; repaired check and six regression gates pass under nested UP/MP/TCG |
| Native build 10 9A suite | UP and TCG 24/24; MP 21/24, premature crash-dialog input; failed run retained |

Build 11 adds a dialog-ready marker and the harness waits for it. Compilation
and 26 host tests pass; the focused two-vCPU KVM 9A rerun passes 24/24
(`dialog-ready-mp-01`). Build 11 UP/TCG are untested. Exact evidence is in
[the continuation](merlin-dialog-readiness.md). No general repair capability,
physical hardware support or registered-VM deployment follows from these
results. The browser's intermittent `chrome.dll+0x842214` failure remains open.
[Image and model evidence](merlinai-milestone9.md).

## MerlinAI (Milestone 9), 2026-11-21

Lab runs use overlays of `XP25-M9-Baseline.qcow2` (`a3bde9b2…5e08`), with
MerlinAI installed by its own installer. The demonstration uses
`XP25-M9-MerlinAI.qcow2` (`0f04a438…4d32`).

| Test | KVM UP | KVM two-vCPU | TCG |
| --- | --- | --- | --- |
| 9A lab suite, native build 06 (crash dialog, consent transfer, SYSTEM crash without a dialog, queue and deduplication, local discovery, Control Panel replacement, UI build request, authenticated health report, uninstall/restore, normal turn-off) | 22/22 (`up-08`) | 22/22 (`mp-02`) | 22/22 (`tcg-02`; the Control Panel window step is skipped under TCG) |
| 9A lab suite, native build 08 (+ category 5, user and Default User policy, their removal) | 24/24 (`up-09`) | 24/24 (`mp-03`) | 24/24 (`tcg-03`) |
| Security `proof` on the M9 baseline | 35/35 | 35/35 | 35/35 (`tcg-02`; `tcg-01` 32/35 kept) |
| Builder job (inside `MerlinAI-Builder`, nested): defect reproduced before the fix, check and regression gates after | before: reproduced; after: pass | after: pass | after: pass |
| Phase 12 demonstration on `XP25-MerlinAI-Demo` (1 vCPU): crash → Send → Build → Review → Apply → fixed, data kept → Roll Back → defect back | Pass, interactive, after three agent fixes (failures kept) | Not tested | Not tested |

**Not tested:** a real AI model investigation, any defect other than the
controlled MerlinTest.exe NULL dereference, components other than MerlinAI's
own being rebuilt, a limited (non-administrator) user's Control Panel after
install, a builder outside this host, the demonstration under two-vCPU KVM
or TCG. **Known:** with the first MerlinAI release (the one in
`XP25-M9-MerlinAI.qcow2`), the Control Panel "Security Center" tile still opens
Windows Security Center. Build 08 fixes it, but it is not packaged yet.
[Record](merlinai-milestone9.md)

## XP25-Winlogon-Fix VM: Supermium replaces Internet Explorer, 2026-11-21

The VM's own disk with Supermium 150.0.7871.255 R2.01 as the only browser and
IE8, MSHTML, JScript, VBScript, `mshta` and Internet Options deleted
(`XP25-Supermium-NoIE.qcow2`, `9e1e8f08…b84d`). Overlays of that exact image,
one-vCPU KVM, 1 GiB:

| Test | Result |
| --- | --- |
| Removal probe after the deleting boot, 27 cases: removed files gone and needed ones kept; `mshtml`/`jscript`/`vbscript` not loadable (126); five engine COM classes unregistered, shell classes working; web handlers on `XP25Browser.exe`, `.hta`/`.mht`/`ftp` without a command; `iexplore` does not start; App Path, Active Setup and type library gone; nothing pending; User Accounts applet opens the classic dialog | Pass (`vm-verify-04`) |
| `.js` file under `cscript` | Does not run (exit 1): the engine is gone |
| XP25 Help self-test (Start-menu Help) | Pass |
| Supermium shell integration: associations, shortcuts, Start-menu client, policy (15 cases) | Pass |
| ShellExecute http, https, `.html`, `.htm`, `.url`; `javascript:` shortcut refused | Pass |
| DevTools: modern JavaScript, tabs, certificate matrix, download, appearance; any public HTTPS site through the gateway (`www.wikipedia.org`, TLS 1.3); link-local address not loaded | Pass, 11/11 |
| Profile and settings persist across a browser restart | Pass |
| Compatibility suite with the MSI built by `msi.dll` (no VBScript) | Pass, except Remote Registry: disabled by the image's baseline (error 1058), as designed |
| AI suite 55/0, provider 7/0 | Pass |
| Security lab `proof` | 34/35: the audit lists four USB drivers the disk already had; the unchanged reference disk fails the same gate |
| Screen-saver probe (10 gates) | Pass |
| Two-account switch oracle | Pass, 9/9 (`-02`; `-01` kept: 8/9, oracle captured the gap before the dialog) |
| In the VM: Start-menu Internet = Supermium, Wikipedia loads through the host gateway, `iexplore` not found, logoff | Pass, by screenshot |

**No longer works** (engine removed, by design): Help and Support pages, `.chm`
help, `.hta`, `.js`/`.vbs`, Outlook Express HTML mail, the Network Setup Wizard,
Active Desktop web content. **Not tested:** two-vCPU KVM, TCG, the `firewall`,
`standard-user` and `ai-repeat` roles, the Winlogon lifecycle harness, other
sites and web applications.
[Record](supermium-replaces-ie.md)

## XP25-Winlogon-Fix VM with R-0 and R-1, 2026-11-20

The interactive VM's own disk with `winlogon.exe` `020eaf40…`, `win32k.sys`
`f698e04d…`, `user32.dll` `4cccacd3…` and `gdi32.dll` `13e538d3…` replaced
(`XP25-R0-R1.qcow2`, `c5183228…`).
- On overlays of that exact image (one-vCPU KVM): two-account switch oracle 9/9;
  screen-saver probe 10/10 (`image01-ss-up-04`; runs `-01` to `-03` kept as
  failed, from COM1 line loss).
- In the VM itself: boot, logon, logoff, by screenshot.

**Not run** on this disk: two-vCPU KVM, TCG, the lifecycle harness and the
security-lab roles. Those ran on 8.2-image overlays with the same four files
(R-0, R-1 sections above).
[VM record](virt-manager-xp25-winlogon-fix.md#redeploy-with-r-0-and-r-1-2026-11-20)

## Source-built core fixes (R-1) checkpoint, 2026-11-19

Fresh overlays of `XP25-CVE-Hardened-8.2.qcow2` (`5a84781f…`). Patched build 02
staged in each run: `win32k.sys` `f698e04d…`, `user32.dll` `4cccacd3…`,
`gdi32.dll` `13e538d3…`. Evidence `.work/r1-20261119/`.

| Test | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| `r1core` probe: no handle to the GDI table section; 34 `.ani` + 150 `.cur` load and draw; WMF and EMF play | Pass (`r1-up-03`; shipped binaries hold the handle: `r1-base-up-02`) | Pass | Pass |
| Security lab `proof` (AI build 17, R-0 Winlogon) | Pass, 35/35 | Pass, 35/35 | Pass, 35/35 |

**Not tested** in the guest: Far East (NLS) keyboard layouts, path-flattening
allocation failures, and malformed cursor, icon or WMF files (covered by host
ASan tests only where portable). The patched binaries are in no packaged image.
[Record](source-built-component-assessment.md)

## Screen savers and idle lock (R-0) checkpoint, 2026-11-19

Fresh overlays of `XP25-CVE-Hardened-8.2.qcow2` (`5a84781f…`, unchanged) with
the R-0 Winlogon `020eaf40…` installed in each run. Evidence
`.work/screensaver-20261119/`.

| Test | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| Screen-saver probe: 10 gates (non-secure, secure by key, secure by Ctrl+Alt+Del, locked station, logon desktop, notices stop, relogon) | Pass (`ss-up-02`) | Pass (`ss-mp-02`) | Pass (`ss-tcg-02`) |
| Two-account switch oracle | Pass, 9/9 | Not run | Not run |
| Winlogon lifecycle harness | Pass | Pass | Pass |
| Security lab `proof` (AI build 17) | Pass, 35/35 | Pass, 35/35 | Pass, 35/35 |
| Security lab `standard-user` | Pass, 12/12 | Not run | Not run |

Observed in the guest: `ssstars.scr` (user, secure and not), `logon.scr`
(`.DEFAULT`, as SYSTEM). Display Properties, other savers, a monitor
power-down (request 2) and Group Policy screen-saver settings are **not tested**.
[Record](winlogon-screen-saver.md)

## Modernization (Milestone 8.4) checkpoint, 2026-11-19

Fresh overlays of `XP25-CVE-Hardened-8.2.qcow2` (`5a84781f…eada`, unchanged) with
native AI build 17 (`xp25agent.dll` `e4638922…`, `XP25Broker.exe` `e328cc76…`,
`ClippyAI.exe` `2d1555db…`, `RoverAI.exe` `c1352991…`, `RoverAIBand.dll`
`480d6d5b…`) and the Milestone 8.4 Winlogon `289abb03…` installed in each run.
None of these runs used a packaged image. Evidence root `.work/modernization-20261118/`.
Afterwards the Winlogon alone was packaged into the XP25-Winlogon-Fix VM's disk
(`471e1b06…`; two-account oracle 9/9 on one-vCPU KVM,
[record](virt-manager-xp25-winlogon-fix.md#update-to-the-milestone-84-winlogon-2026-11-19)).
AI build 17 is not in any packaged image.

| Test | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| Full regression (`proof`): logon, licensing, Explorer, AI suite 55 + provider 7, compatibility suite, security probes, baseline verification, programs and games, network capture — 35 gates | Pass | Pass | Pass |
| Firewall (`firewall`): filtering, permitted port, administrator control, refusal, restart window, reboot persistence — 27 gates | Pass | Pass | Pass |
| AI suite three times under host load (`ai-repeat`) — 14 gates | Pass | Pass | Not run |
| Standard user (`standard-user`) — 12 gates | Pass (`m84-std-up-02`; `-01` kept: two COM1 markers lost at logon, see below) | Pass | Pass (`m84-std-tcg-02`; `-01` kept: two unplanned resets, see below) |
| Winlogon lifecycle (main-tree harness: 18 gates, then lock/unlock after a logoff, restart and relogon, Turn Off) | Pass | Pass | Pass |
| Two-account switch oracle (9 switches, wrong password refused) | Pass | Not run | Not run |
| ClippyAI exit while an approval is open (`clippyexit`, 3 cycles, with and without full page heap) | Pass (94–157 ms; build 14: 15.06–15.19 s) | Not run | Not run |
| Idle session past the screen-saver timeout (`idle`): COM1 openable, log growth | Pass (104/104, 0 B/min; 8.2 Winlogon: 70/110, 23,520 B/min) | Not run | Not run |
| `/GS` cookies initialized at run time (`gscookie`, 8 readings in 4 processes) | Pass | Not run | Not run |

Two standard-user runs failed and are kept. `m84-std-up-01` lost its first two
COM1 markers at logon, because Winlogon opens the exclusive port for every event
(roadmap R-0b); the account was created correctly. `m84-std-tcg-01` reset twice
without a shutdown record, each time 5–7 s after the browser case started the
Remote Access Connection Manager. No dump was written; the same start passed in
Milestone 8.1's TCG run and in the rerun. This is consistent with an intermittent
failure on the checked kernel (assertions bugcheck and restart with no debugger),
but it is **not explained** (roadmap R-13).

The changes keep every interface: no export, import, structure, registry value
or file format changed. Screen savers did not start in this checkpoint (see R-0
below).
Not tested: real networks and hardware, the Explorer-bar unload race
(code-level fix, not reproduced), AI load under TCG.
[Audit](architecture-modernization-audit.md) ·
[static analysis](static-analysis-findings.md) ·
[optimization](optimization-opportunities.md) · [roadmap](modernization-roadmap.md)

## Historical CVE remediation (Milestone 8.2) checkpoint, 2026-11-13

Image `XP25-CVE-Hardened-8.2.qcow2` (`5a84781f…eada`): the Milestone 8.1 image with the
rebuilt `lsasrv.dll` that fixes MS04-011 (CVE-2003-0533). Evidence root
`.work/cve82-20261112/`. Only `lsasrv.dll` changed from the parent.

| Test | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| Cold boot, XP25 Winlogon logon, `licdll` admission, Explorer identity (patched lsasrv.dll authenticates) | Pass | Pass | Pass |
| MS04-011 DsRole: hostile over-long name does not crash LSASS; upgrade not granted (`cve82-verify-*`) | Pass | Pass | Pass |
| Full regression: AI 55/0 + 7/0, compatibility suite, firewall, programs (`cve82-proof-up-01`) | Pass | Not re-run (same binary as UP) | Not re-run |
| MS04-011 overflow reachable at runtime through the DsRole API | No — the request returns ERROR_NOT_SUPPORTED on this workstation SKU before logging; the overflow is proven and fixed at the source/host level | — | — |

No compatibility change from Milestone 8.1: the fix is a bounds check plus an
access check inside LSASS and does not alter any interface behaviour for a
legitimate caller. Not tested: real networks and hardware, domain promotion
(unsupported on this SKU), the deferred CVEs. [Audit](historical-cve-audit.md) ·
[remediation](historical-cve-remediation.md).

## Security baseline 8.1 (Milestone 8.1) checkpoint, 2026-11-13

Image `XP25-Security-Baseline-8.1.qcow2` (`501c7986…fda4`): the Milestone 8 image
with baseline version 2, the 8.1 security tools and AI build 14. Evidence root
`.work/security81-20261112/`. Two-vCPU runs add the multiprocessor kernel and
HAL.

| Test | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| Cold boot, XP25 Winlogon logon, `licdll` admission, Explorer identity | Pass | Pass | Pass |
| Windows Firewall: running, filtering, permitted port, removal, administrator control, unprivileged attempts refused, restart window (`fw-*`) | Pass | Pass | Pass |
| AI suite 55/0 and provider 7/0 (`proof-*`) | Pass | Pass | Pass |
| AI suite three times under moderate host load (`ai-load-*`) | Pass | Pass | Not run |
| Established compatibility suite, MSI install and removal (`proof-*`) | Pass | Pass | Pass |
| Programs and games installed with Windows: start, respond, close | Pass; Hearts crashes on close (also on the unhardened base) | Same | Same |
| Standard user: logon, desktop, AI, IE8, programs, restart, power-off (`std-*`) | Pass | Pass | Pass |
| Rollback of the security configuration | Pass (Milestone 8) | Pass (`rollback-mp-01`) | Not run |
| Logoff, then logon as another account without a restart | **Not established on this image**: after a logoff the logon dialog's fields do not paint (XP25 Winlogon defect; also on the unhardened base); the lab could not log on through them. Root cause and fix: [account-switch fix](winlogon-account-switch-paint.md) (2026-11-17); with the fixed Winlogon on fresh overlays of this image: **pass** (9/9 switches, two accounts) | Same; fixed Winlogon on overlays: **pass** (9/9) | Same; fixed Winlogon on overlays: **pass** (5/5) |

Compatibility changes of baseline version 2:

| Change | Effect on use |
| --- | --- |
| NetBIOS over TCP/IP as a point-to-point node | No NetBIOS name broadcasts or broadcast resolution (already ineffective with the broadcast-response setting); WINS, DNS, `hosts`, `lmhosts` work |
| `%SystemRoot%\Tasks` for administrators only | Standard users cannot create scheduled tasks; existing tasks run |
| Firewall, Security Center and XP25 broker services controlled by SYSTEM and administrators only | Power Users can no longer stop, pause or restart them |
| XP25 broker for standard users: AudioSrv, Spooler, stisvc, Themes only (without an administrator's policy) | ClippyAI cannot restart DNS Client, DHCP, BITS, Task Scheduler and the other network or system services for a standard user; an administrator can allow them |

Observed: Internet Explorer 8 shows its "Set Up Windows Internet Explorer 8"
wizard on each user's first start. Under libvirt (`XP25-Security-8.1`, adds a
USB tablet and an empty CD-ROM drive; screenshots only) the image boots, logs on
with licensing admission and reaches the desktop; the Found New Hardware Wizard
opens at the first logon ([record](virt-manager-xp25-security-81.md)). Not tested: real networks and hardware,
third-party applications and games, Fast User Switching, Remote Desktop,
printing. [Record](security-regression.md).

## Security baseline (Milestone 8) checkpoint, 2026-11-12

Hardened image `XP25-Security-Baseline.qcow2` (`6da7d04e…45d9`): AI image-05 plus
the XP25 Winlogon build 10, the relinked kernel that exports
`KeFlushQueuedDpcs`, AI build 11 and the applied security baseline. Evidence
root `.work/security-20261111/` (`W`). "Image" columns are fresh overlays of the
standalone image; two-vCPU runs add the multiprocessor kernel and HAL.

| Test | 1 vCPU KVM | 2 vCPU KVM | TCG |
| --- | --- | --- | --- |
| Combination before hardening: AI 55/0 + 7/0, compatibility CD, XP25 Winlogon logon (`pre-up-02`) | Pass | Not run | Not run |
| Install, apply, restart, verify on the combined base (`harden-*`) | Pass (`harden-up-04`) | Pass (`harden-mp-03`) | Pass (`harden-tcg-02`) |
| Image cold boot: NT 5.1 boot, XP25 Winlogon logon, `licdll` admission, Explorer identity | Pass (`proof-up-02`) | Pass (`proof-mp-02`) | Pass (`proof-tcg-03`) |
| Image: AI suite 55/0 and provider checks 7/0 | Pass | Pass | Pass |
| Image: standard, pointer, session, network, service, GINA, UserEnv, branding, shell, profile probes | Pass | Pass | Pass |
| Image: MSI install and removal (application installation) | Pass | Pass | Pass |
| Image: Remote Registry probe | Refused while disabled (error 1058), **passes after an administrator re-enables the service**; baseline re-applied | Same | Same |
| Image: ordinary account, restricted token and administrator security probe | 71 / 73 / 36 cases, 0 failures | Same | Same |
| Image: nothing reachable from the adjacent network (TCP, UDP, ICMP, repeated NetBIOS probes) | Pass | Pass | Pass |
| Image: baseline verified after restart and after the workload | Pass | Pass | Pass |
| Image: guest-requested power-off | Pass | Pass | Pass |
| Rollback restores the recorded configuration (`rollback-up-02`) | Pass | Not run | Not run |

Compatibility changes made by the baseline (each reversible with `XP25Sec
rollback` or by an administrator):

| Change | Effect on use |
| --- | --- |
| Server, Computer Browser, Remote Registry, SSDP, UPnP host, WebDAV, IPSEC Services, Remote Assistance, NetMeeting sharing, Automatic Updates, Error Reporting disabled | The computer shares nothing, is not remotely administered, has no IPsec/L2TP, no Windows Update. Access to other computers' shares still works |
| Firewall on, no replies to own broadcasts | NetBIOS names are not resolved by broadcast; a program that finds LAN peers by broadcast needs its firewall exception. DHCP works |
| Internet zone without script, ActiveX, Java; machine-only zones | Internet pages in IE and embedded browsers lose active content; local, intranet and trusted zones unchanged |
| Script files open in Notepad on double-click | `cscript`/`wscript` run them when named |
| AutoRun only for optical media | USB and network media never auto-start a program |
| Administrators group owns what an administrator creates | A program that compares a file's owner with the user sees the group |
| XP25 broker refuses the firewall and Security Center; offers only desktop services | ClippyAI cannot restart those services |

Defects recorded, not changed:

| Item | Observation | Evidence |
| --- | --- | --- |
| `shutdown.exe`, `InitiateSystemShutdown` under the XP25 Winlogon | "The network path was not found": the `InitShutdown` RPC interface is not served. `ExitWindowsEx` and Start → Turn Off work | `W/runs/pre-up-02`, `pre-up-02-extract/xp25/shut.txt` |
| Server service, `http.sys` | Cannot start on the source-built kernel (`RtlIpv4AddressToStringExW`, push-lock exports missing). The Server service is disabled by the baseline anyway | `W/import-check-01/report.json`, System log 7023 |
| `sfc /scannow` | Would be expected to replace the 25 source-built system files; Windows File Protection is not hosted by the XP25 Winlogon | Not executed; file inventory `W/offline-audit-03` |
| AI cases `provider_reconfigured_wrong_secret` and `clippy_minimizes_to_tray` | Each failed once while other guests ran on the host (`harden-up-02`, `proof-tcg-02`); both pass in every run made alone | `W/runs/harden-up-02`, `W/runs/proof-tcg-02` |

Not tested: real networks and hardware, other NIC models, the image in the
libvirt VMs, third-party applications and games, Fast User Switching, Remote
Desktop, printing. [Regression record](security-regression.md),
[inventory and trade-offs](security-baseline.md).

## Browser network-security verification — Phase 2 correction and final coverage (Milestone 7B), 2026-11-11

The Phase-2 ShellExecute render gap is corrected and the complete two-vCPU KVM regression
re-run through the gateway is clean. Base = 7A image `6cad84c6…` over a throwaway overlay;
MP two-vCPU KVM; browser HTTPS routed through the Phase-1 gateway. Correction is in
`build/browser_test_media.py` (committed); evidence root `.work/browser-7b3-20261111/`
(`X3`), clean run `runs/b7reg4-mp`. Still **experimental, not Internet-safe/accepted**.

| Test | Result | Evidence |
| --- | --- | --- |
| ShellExecute internal HTTP/URL render (the 2 previously-open cases) | **PASS** — `rendered_ShellExecute_HTTP` and `_URL` now render; shell fixtures reach the in-ns server directly | `runs/b7reg4-mp`, `http.jsonl` |
| Explorer/Luna shell-association launch (HTTP/HTML/HTM/URL/HTTPS + rejected scheme) | **PASS** — 5 verbs launch exit 0, rejected scheme `=87`, all four render receipts green | `runs/b7reg4-mp/serial.log` |
| JavaScript, multiple tabs, downloads, appearance (Luna) set/persist | **PASS** (`modern_javascript`, `multiple_tabs`, `download_completed`, `appearance_setting_changed/persists`) | `runs/b7reg4-mp/cdp-browser/result.json` |
| HTTPS certificate matrix through the gateway | **PASS** — valid loads; expired/wrong-host/untrusted each rejected `ERR_CERT_*` end-to-end | `runs/b7reg4-mp/cdp-browser/result.json` |
| Browser profile persistence across restart; browser restart; normal shutdown | **PASS** (`profile_persists`, reopen exit 0, `{"guest":true,"reason":"guest-shutdown"}`) | `runs/b7reg4-mp` |
| AI regression (62 cases) | **PASS** (`passes=55/0` and `7/0`) under low host load | `runs/b7reg4-mp/serial.log` |
| Unauthorized destinations still blocked | **PASS** — 79 denies (70 `not_allowlisted` phone-home + 9 non-CONNECT), 11 allows only to the 4 approved cert hosts; no bypass | `regression4-gateway.log` |
| `full_regression_coverage` | **false** — 4 unchanged `not_tested` probe cases (documented gap, **not** a regression) | `runs/b7reg4-mp/browser-results.json` |
| XP25-AI assistant suite flakiness (RoverAI indexer / Clippy tray) | Intermittent **timing-race** under back-to-back host load (runs 1–3: 3/1/7 varying case fails); **cleared under low load** (run 4, 55/0). Pre-existing/environmental, non-browser, not caused by the fix (AI-suite bytes identical to the 8 prior passing runs). | `logs-b7reg2-mp`, `logs-b7reg3-mp` |

Fix mechanism: a managed Supermium proxy policy (`HKLM\SOFTWARE\Policies\Supermium`
`ProxyMode=fixed_servers`, `ProxyServer=10.25.0.1:3128`,
`ProxyBypassList=xp25.test;localhost;127.0.0.1;10.25.0.1`) is **added** so every browser
launch path (shell association and command line) routes real egress through the gateway
while reaching the internal `xp25.test` host directly; the Phase-1 WinINET proxy is
preserved unchanged (purely additive) and the pinned test ISO is byte-identical
(`7ca80511…`). Host-enforced isolation (namespace with no uplink + gateway allowlist) is
**not** weakened — a guest proxy setting only decides where the browser *attempts* to send
traffic, and the namespace has no route to the Internet regardless.
[Milestone 7B architecture, residual risk and open items](browser-security-7b.md)

## Browser network-security verification (Milestone 7B, Phase 2) checkpoint, 2026-11-10

Phase 2 verified the Phase-1 design against an explicit bypass matrix and ran the full
practical regression through the gateway, all host-observed. Base = 7A image
`6cad84c6…` over throwaway overlays; MP two-vCPU KVM. Evidence
`.work/browser-7b2-20261110/`. Still **experimental, not Internet-safe/accepted**.

| Test | Result | Evidence |
| --- | --- | --- |
| Gateway bypass matrix (not-allowlisted, direct-IP, metadata, loopback, IPv6-literal, wrong-port, non-CONNECT, CRLF, DNS-rebind, live-TLS allow) | **PASS 11/11** | `gateway-tests/gateway-bypass-matrix.json`, `tests/test_browser_gateway.py` |
| Namespace egress probe (Internet, alt-DNS, host LAN, router, libvirt/LXD/docker, metadata, IPv6 = no-route; gateway-down = refused; control reachable), with and without nft | **PASS 12/12 ×2** | `isolation-fw/`, `isolation-nofw/`, `vm/network_isolation_probe.py` |
| Full regression through the gateway (JS, tabs, HTTPS cert matrix, downloads, profile+appearance persistence, restart, AI 62, shutdown) | **PASS** (all enumerated items) | `runs/b7reg-mp`, `regression/mp/result.json` |
| Gateway decisions during the run | 12 allow (4 approved hosts) / 51 deny (44 phone-home + 7 non-CONNECT) | `regression-gateway.log` |
| ShellExecute internal-HTTP render (2 cases) | **Not green** — test-proxy artifact (non-CONNECT refused), launches exit 0; not a product/security defect | `runs/b7reg-mp/serial.log` |
| `full_regression_coverage` | **false** — 4 documented `not_tested` probe cases (unchanged gap) | `regression/mp/result.json` |
| Containment re-verify (SAFER token + Job Object) | **PASS** — 12/12 samples denied admin/system (error 5), 6/6 `job_member=1`, controls discriminate; residual = own-profile writable | `runs/b7cont2-01` |
| `0x842214` latest-build review | No supported fix — v150-r2.02 = same Chromium 150.0.7871.255; upstream still working it | `gpu-0x842214-update-review.json` |
| Recovery (disposable discard, clean cold-boot 15/15, gateway restart 9/9, infra unaffected) | **PASS** | `recovery/`, `runs/b7coldboot-01`, `host-state/` |

## Browser secure Internet containment (Milestone 7B, Phase 1) checkpoint, 2026-10-28

Host-enforced network containment for the disposable XP25 browser VM, verified
independently from the host (pcap + nftables drop counters + gateway log), no sudo,
no global-firewall change. Base = 7A image `XP25-Browser-Experimental.qcow2`
(`6cad84c6…`) over a throwaway overlay; MP kernel/HAL (two-vCPU KVM). Allowlist =
`example.com`/`www.example.com`/`example.org`/`example.net`; unrestricted browsing
disabled. Browser still **experimental, not Internet-safe/accepted** (no NT 5.1
renderer sandbox; intermittent `0x842214`).

| Test | Result | Evidence |
| --- | --- | --- |
| Gateway allow/deny logic (host, live DNS+TLS) | **PASS 8/8** — example.com allowed w/ real cert; non-allowlisted, public direct-IP, metadata, loopback, port 22, non-CONNECT, rebind-to-nonglobal all denied | `.work/browser-7b-20261028/gw-test-02.log` |
| Approved HTTPS loads in guest (`https://example.com/`) | **PASS** — 2 gateway allows to global IP `104.20.23.154`, 264 proxy pkts, E2E TLS, clean shutdown | `.work/browser-7b-20261028/runs/b7net-03` |
| Unapproved host / LAN / host services / other VMs / metadata | **PASS (blocked)** — 0 packets leave `10.25.0.0/24` (pcap); no default route; non-allowlisted denied at gateway | `b7net-03/network.pcap`, `gw-run-01.log` |
| Unauthorized DNS / IPv6 bypass | **PASS (blocked)** — only `xp25.test` local DNS; nft drops IPv6 (counter 12) and guest off-service pkts (counter 23) | `b7net-03/nft-counters.txt` |
| Gateway-down ⇒ no Internet (fail-closed) | **PASS** — sole egress is the gateway socket | design; `b7net-01` |
| Browser-process containment (SAFER token + Job Object) on 7A image | **PASS (re-verified)** — `b7cont-01`: all 6 browser processes (root+2 renderer+2 utility+gpu) denied system32/SYSTEM-inject/admin-file/registry (error 5); baseline could, known-restricted could not. Admin/SYSTEM boundary only, not a renderer sandbox. | `.work/browser-7b-20261028/runs/b7cont-01` |
| Regression matrix (secure config): single-vCPU (UP) | **PASS (OS + isolation)** — clean boot/shutdown, 0 off-subnet leak; approved-HTTPS browser nav NOT demonstrated on UP (single-vCPU cold-start too slow, UI-bound >130s; proven on MP) | `b7net-up-01` |
| Regression matrix (secure config): TCG practical (non-DevTools) | **PASS** — clean boot/shutdown, 15/15 shell checks, 0 off-subnet leak, nft drops; browser nav impractical under emulation | `b7tcg-01` |
| Full DevTools functional regression over the gateway | **NOT RE-RUN this session** — PASS previously | `matrix-150-02` |

Details, architecture, firewall rules, gateway hardening and rollback:
[secure Internet browsing — architecture and evidence](browser-security-7b.md)

## Browser offline integration (Milestone 7A) checkpoint, 2026-10-27

| Test | Result | Evidence |
| --- | --- | --- |
| GPU config vs 0x842214 (A/B, 12 cycles each, XP25 KVM) | Investigated: no config avoids it. `--disable-gpu` (default) 0 hits/12 this run; `--in-process-gpu` removes the gpu-process but relocates the CHECK to utility/renderer (14 hits); both render 12/12. Kept `--disable-gpu`; rejected `--in-process-gpu`. | `.work/browser-fix-20261026/collect-gpuab-01`, `milestone7a-summary.json` |
| Single-vCPU KVM, 20 launch/navigate/close cycles | **PASS** — 20/20, 0 failed, 20 JS receipts | `.work/browser-fix-20261026/runs/fstab-up-01` |
| Two-vCPU KVM, 20-cycle loop | **PASS** — `fstab-mp-04` on the **MP kernel/HAL base `582d551d`**: 20/20 clean cycles (`root_code=0`), 0 non-zero exits/157, 0 `0x842214`/CHECK, 15/15 shell checks, clean guest shutdown. (Earlier `fstab-mp-01/02/03` halts were an operator error — UP base `ec22f45b` under −smp 2, whose UP HAL BSODs; corrected.) | `.work/browser-fix-20261026/runs/fstab-mp-04`, `matrix-150-02` |
| TCG practical offline functional (render + 5 ShellExecute types, non-DevTools) | **PASS** | `.work/browser-fix-20261026/runs/fmatrix150-02-tcg` |
| Offline image (experimental) `XP25-Browser-Experimental.qcow2` + cold boot | **PRODUCED + VERIFIED (experimental)** — fresh install on MP base → packaged standalone (no backing file, 292 file hashes re-verified), SHA-256 `6cad84c6…`; cold-boot of a fresh overlay passed 15/15 shell cases (0 failures) with clean guest shutdown. Kept experimental, not Internet-safe/accepted. | `.work/browser-fix-20261026/offline-image-01`, `runs/offline-install-01`, `runs/offline-coldboot-01` |

0x842214 remains an intermittent, sometimes-fatal blocker that no GPU config
avoids → the offline browser (and its packaged image) stays **experimental**; no
assertion suppressed, no image falsely accepted. The image deliverable is produced
under its honest `XP25-Browser-Experimental.qcow2` name (manifest
`experimental_unaccepted`), not styled as an accepted `XP25-Supermium-Offline.qcow2`.
[GPU investigation, stability, image recipe and status](browser-offline-7a.md)

## Browser security hardening (Milestone 7B) checkpoint, 2026-10-27

| Area | Result | Evidence |
| --- | --- | --- |
| Renderer sandbox (Chromium native) | Unavailable on NT 5.1: Supermium compiles it off for all pre-Win10 (`renderer_main.cc:249`, GDI/DirectWrite + Vista+ integrity levels); inside `chrome.dll`, not re-enablable from our layer. Documented, not faked. | `.work/browser-fix-20261026/sandbox-analysis-01/nt51-sandbox-capability.json` |
| Process-tree containment (alternative architecture) | Implemented in `XP25Browser.exe`: SAFER Normal User token + Job Object, inherited by all children. Verified live (MP KVM): tree `member=1` in job; denied (error 5) admin file/registry, `%WINDIR%\system32`, SYSTEM-process injection; pages render. | `.work/browser-fix-20261026/runs/fcontain150-mp-02`, `contain-02-extract` |
| Host-enforced network isolation | No passwordless root → libvirt NAT + nftables firewalling out of reach; enforceable model is namespace-with-no-uplink + allowlist CONNECT gateway (default-deny, HTTPS-only, non-global addresses rejected). Documented limitation. | `vm/browser_network.py`, `vm/browser_gateway.py` |
| Secure config | TLS on; no `--no-sandbox`/`--remote-debugging-port` in the install; `URLBlocklist=*`; profile isolated by the restricted token. Extension/plugin/legacy-protocol hardening outstanding. | `build/browser_config.py`, `components/browser/browserctl.c` |

NT 5.1 cannot provide integrity levels, AppContainer, Win32k lockdown or UIPI, so a
compromised renderer shares the browser token and the user profile; Internet stays
disabled by default. No renderer sandbox or kernel mitigation is claimed that is not
enforced. [Milestone 7B architecture, residual risk and open items](browser-security-7b.md)

## Browser KVM regression + 0x842214 checkpoint, 2026-10-27

| Configuration | Result | Evidence |
| --- | --- | --- |
| Supermium 150, KVM single-vCPU (up) + two-vCPU (mp), 2 GB, disk headroom | Full DevTools regression passes: modern JS, local HTML, multi-tab, HTTPS valid + reject expired/wrong-host/untrusted, download, Internet-block policy (lab subdomain + public site), profile + appearance persistence across restart, 55+7 AI cases, normal shutdown. Only non-pass is the explicit `full_regression_coverage` marker (login_transition/legacy_games/security_mitigations/shutdown `not_tested`). | `.work/browser-fix-20261026/matrix-150-02`, `matrix-150-02-summary.json` |
| Supermium 150, TCG, 2 GB | Shell + all 5 ShellExecute types render (4 JS receipts); DevTools CDP calls exceed the 45 s timeout under single-thread emulation (harness/timing, not a crash). Timeout now configurable (`XP25_CDP_TIMEOUT`, 240 s for TCG); re-run in `matrix-150-03`. Guest frozen as failure. | `.work/browser-fix-20261026/runs/fmatrix150-02-tcg`, `matrix-150-03` |
| 0x842214 handle-type CHECK (gpu-process field-trial Section) | Characterized: inherited `--field-trial-handle` value reads as `File`, not `Section`, at the CHECK. Isolated progwrp handle-list inheritance preserves the Section on XP25 **and** stock SP3; reproduces on stock SP3 → browser gpu-process handle-lifetime defect, not the compat proxy or XP25. Intermittent. No safe compat-layer fix; not patched. | `.work/browser-fix-20261026/collect-fab150-sp3-up-01`, `runs/finherit-{xp25,sp3}-up-02`, `crash-842214-summary.json` |

Earlier DevTools timeouts were host storage contention, not a browser defect. The
`0x842214` CHECK and the four `not_tested` probe cases remain open; no new accepted
or Internet-safe image is produced.
[Watcher fix, containment, KVM regression and 0x842214 detail](browser-stability-security.md)

## Browser watcher fix and containment checkpoint, 2026-10-27

| Configuration | Result | Evidence |
| --- | --- | --- |
| XP25 pwrp_k32 proxy, `browser_watch` probe, XP25 KVM + original SP3 | `failures=0` both: exited-issuer IOCP watches complete with the proxy (32/32 concurrent) where `kernel32`/original return error 995; event/routine/error parity with `kernel32`. | `.work/browser-fix-20261026/collect-fab150-xp25-up-01`, `collect-fab150-sp3-up-01` |
| Supermium 150 watcher CHECK, A/B original-vs-proxy, XP25 KVM 2 GB | `0x77b96f8` fires in an original-wrapper block (first+second chance) and in no proxy block (2 vs 0). Residual: one proxy-block hang; guest later wedged and was frozen. | `.work/browser-fix-20261026/fab150-xp25-up-01-ab-report.json`, `runs/fab150-xp25-up-01/failure.json` |
| Reduced-privilege launch (SAFER Normal User), Supermium 150 MP KVM 2 GB | Browser root and children denied admin-only file+registry writes (error 5) under launcher and shell-association launch; renderers observed; page rendered. Not a renderer sandbox: user profile still writable, no UIPI on NT 5.1. | `.work/browser-fix-20261026/runs/fcontain150-mp-01` |
| Install-only image (proxy + launcher + Internet policy), XP25 UP KVM | Normal shutdown; rejects `javascript:`/extra-arg/non-HTML (87) with no browser launched. | `.work/browser-fix-20261026/runs/finstall150-01` |
| Supermium 150 shell + reduced-token rendering, KVM-UP / KVM-MP / TCG | 13 shell/association/policy checks pass; HTTP/HTML/HTM/URL/HTTPS rendered (5 receipts/mode). DevTools deep-regression (nav/tabs/certs/download/persistence) `Not tested`: CDP WebSocket timed out under ~98%-full-disk contention; guests frozen as failures. | `.work/browser-fix-20261026/matrix-150-01`, `fix-summary.json` |

Internet browsing is disabled by default in the experimental image
(`URLBlocklist=*`, local/internal/lab allowlist only). No renderer sandbox exists
on NT 5.1; containment is process-level. No CHECK removed, no API faked, no shared
IE DLL deleted, no new image accepted.
[Watcher fix, containment method and exact limits](browser-stability-security.md)

## Browser stability/security checkpoint, 2026-10-26

| Configuration | Result | Evidence |
| --- | --- | --- |
| Supermium 150, matched original SP3/XP25 KVM, 2 GB | SP3 root shutdown crashes; XP25 Cirrus captures the same watcher CHECK/error 995 in network service. Short repeated passes do not establish stability. | `.work/browser-stability-20261026/control150-capture-01`, `xp25150-cirrus-capture-01` |
| Supermium 150, XP25 TCG, 2 GB | First close times out; no JS receipt. | `runs/bdiag150-xp25-tcg-01` under the same evidence root |
| Supermium 144, XP25 MP/KVM, 2 GB, unmonitored | Three abnormal root exits; two of three JS receipts. Debugger run instead times out. | `runs/bplain144-xp25-mp-01`, `runs/bdiag144-xp25-mp-01` |
| Supermium 144 executing renderers on SP3 and XP25 | Primary/main-thread token boundary tests fail; isolation is not acceptable. Both 144 and 150 are unsuitable for unrestricted Internet access. | `runs/btrace144-sp3-up-01`, `runs/btrace144-xp25-up-01` |
| Native desktop Help | Original NT compiler builds; real Start-menu launch on XP25 KVM; 14 GUI-control tests pass on SP3 KVM and XP25 TCG without MSHTML/JScript/VBScript. Original Help recovery works in a new overlay. | `native-08`, `runs/native-help-up-01`, `runs/help-contract-xp25-tcg-01`, `runs/native-help-rollback-up-01` |

No shared IE DLL is removed. No new engineering image is accepted. Full browser,
HTTPS, application and AI regression acceptance remains incomplete.
[Failure analysis, security method and exact limits](browser-stability-security.md)

## XP25-AI with the XP25 gateway on the KVM host, 2026-11-11

| Configuration | Result | Evidence |
| --- | --- | --- |
| XP25-AI (libvirt KVM, overlay on image-05), RTL8139 hot-plugged into the running guest, slot 3 | Enumerated without a wizard; DHCP lease `10.25.0.13` | `.work/xp25-ai-gateway-20261111` |
| ClippyAI → XP25 gateway (`10.25.0.1:8443`, revision `c4f4b00e…`) → OpenAI Responses API, `gpt-4.1-mini` | Pass: *Test connection* "Connected. The model replied: READY" | `04-test-result.png` |
| libvirt nwfilter `xp25-gateway-only` (ebtables, no `br_netfilter`) | DHCP passes; host ICMP passes; host → guest TCP 139/445 dropped; TCP 139 connects when the filter is removed | `filter-ab.txt` |
| `xp25-gateway.service` as a user-mode unit (no `DynamicUser`, no `ProtectHome`) against the test double | Pass: credentials via `%d`, signed call forwarded, journal audit lines | `unit-test/journal.txt` |
| `xp25-gateway.service` installed as a system service | Not tested (needs root) | — |
| ClippyAI tool use and chat with the real OpenAI service | Not tested | — |

[Record](xp25-ai-gateway.md)

## XP25-AI remote access through Guacamole, 2026-10-26

| Configuration | Result | Evidence |
| --- | --- | --- |
| XP25-AI rebuilt (libvirt KVM, overlay on image-05, no NIC, VNC loopback + password, USB tablet) | 11/11 offline gates; `oem` probe pass; network gates not applicable | `.work/vm-rebuild-20261026/results` |
| MEA web → Guacamole 1.6.0/guacd (Fargate) → relay → SSH-over-SSM tunnel → QEMU VNC, system Chromium 156 | Pass: Start menu by mouse, Notepad text by keyboard, reconnect into the same session, seat held and released | `.work/guacamole-remote-20261026/e2e-02` |
| Windows shortcuts from the browser (Alt+F4) | Not delivered as a shortcut in the headless test | same |
| Clipboard, audio, other browsers, mobile | Not tested | — |

[Record](xp25-ai-remote-access.md)

## Earlier browser modernization checkpoint, 2026-10-25/26

Official Supermium x86 150.0.7871.255 R2.01 passes preliminary single-vCPU
KVM page, JavaScript, tab, download and HTTPS certificate cases with software
rendering on standard VGA. Thirteen default-association/shortcut observations
pass. The original NT compiler builds all three utilities. Final native
KVM 1-vCPU / KVM 2-vCPU / TCG acceptance remains incomplete because browser
crashes/timeouts were observed. Corrected shell launches have positive page
receipts; 24 registry scopes and 12 shortcut paths round-trip through rollback.
A standalone experimental image is generated and explicitly unaccepted. The browser internally
adds `--no-sandbox` on NT 5.1; unrestricted sampled child tokens do not establish
sandbox protection. No certificate bypass is used. Shared IE DLLs and legacy
COM remain; complete Trident removal is unverified.
[Browser evidence, audit, regressions and limitations](browser-modernization.md)

## Interactive XP25-Winlogon and XP25-AI VMs, 2026-10-25

| Configuration | Result | Evidence |
| --- | --- | --- |
| XP25-Winlogon (libvirt KVM, 1 vCPU, 512 MiB, RTL8139 `…:04` on `XP25-Isolated`), independent Winlogon | 16/16 gates; `oem` probe 19/19; `XP25-WINLOGON` at `10.25.0.12` | `.work/vm-config-20261025/together-01/results-XP25-Winlogon` |
| XP25-AI (libvirt KVM, overlay on image-05 `ec22f45b…be2a`, RTL8139 `…:05`), original Winlogon | 16/16 gates; `oem` probe 19/19; `XP25-AI` at `10.25.0.13` | `.../together-01/results-XP25-AI` |
| Both running at once on `XP25-Isolated` | Distinct leases, guest-to-guest ping and NetBIOS names, host ping both, no gateway, outside unreachable | `.../together-01` |
| System Properties with the widened Computer lines (`sysdm.cpl` `98f3c968…`), all seven tabs | Text fits, no overlaps, every page's controls inside, sheet width fits 640×480 | probe records; `rehearsal-ai-01/09-tabs-montage.png` |
| OEM model at 120 and 144 DPI | Font measurement fits 124 DLU; no guest was run at those DPIs | `model_metrics` records |
| Rehearsal overlays (KVM, no NIC, COM1) | AI and Winlogon flows pass; rollback restores both files; one unexplained restart in `rehearsal-wl-01` | `.work/oem-sysdm-20261025/rehearsal-*` |
| WMI computer rename on the Winlogon image | Fails, `0x80041004`; native `SetComputerNameExA` used | `rehearsal-wl-01/failure.json` |

See [the configuration record](xp25-vm-configuration.md); the first OEM pass is in [the OEM record](xp25-winlogon-oem-branding.md).

## XP25 AI components (ClippyAI, RoverAI), 2026-10-25

Native build 10 on the accepted engineering image (original Winlogon, SHA-256
`39112bbd…0296`), see [the milestone record](xp25-ai-clippyai-roverai.md).

| Configuration | Result | Evidence |
| --- | --- | --- |
| QEMU/KVM i440FX, 1 vCPU, 512 MB, RTL8139 in a private namespace | 62/62 AI cases, regression suite exit 0, guest shutdown | `.work/ai-20261025/runs/ai-b10-kvm-up-01` |
| QEMU/KVM i440FX, 2 vCPUs (MP kernel/HAL parent `d46fa4bf…`) | 62/62, regression suite exit 0, guest shutdown | `ai-b10-kvm-mp-01` |
| QEMU TCG, 1 vCPU | 62/62, regression suite exit 0, guest shutdown | `ai-b10-tcg-01` |
| Packaged `XP25-AI-Engineering.qcow2` (`ec22f45b…be2a`), KVM 1 vCPU | 62/62, regression suite exit 0, guest shutdown | `ai-b10-image-proof-01` |
| OpenAI Responses API through the XP25 gateway | Verified against a local test double only | `gateway.jsonl`, `mock-openai.jsonl` per run |
| Real OpenAI service, direct HTTPS from XP | Not tested; direct HTTPS refused by design (SChannel lacks TLS 1.2) | — |
| User-scope DPAPI (`CryptProtectData`) | Fails with 1783 on both engineering images; Credential Manager used | `.work/ai-20261025/bisect/eng0{1,2}-dpapi-b` |
| Physical hardware, other hypervisors, domain logon, non-English UI | Not tested | — |

## Interactive XP25-Winlogon VM, 2026-10-25

`XP25-Winlogon` is a persistent `qemu:///system` domain. Its disk is an
independent byte copy of the 18-gate-verified Winlogon engineering image (SHA-256
`0df7fc05b0b965941f4c488894ce200adcd44d91acf4bf28f93f7a445d30c51c`). Under KVM,
the one-vCPU qemu32/512 MiB/i440fx 8.2/IDE/standard VGA/RTL8139 profile was
observed reaching the independent Winlogon's MSGINA logon. It was also observed
rejecting a wrong password, authenticating `XP25`, completing `licdll` admission
and verifying Explorer identity, then showing Explorer/Luna. Six standard, six
session and fourteen shell observations pass, covering the desktop, taskbar,
Start menu, Luna and folder navigation. Notepad and a guest-requested shutdown
were also observed. Clone MAC `52:54:00:25:00:04` receives `10.25.0.12` from the
isolated libvirt network, and `xp25.test` answers. Lock, logoff, crash recovery,
MP/TCG, service and network-probe cases were not repeated for this registration.
No broader hardware or application claim is made.
[Exact settings, evidence and limitations](virt-manager-xp25-winlogon.md)

## Independent Winlogon desktop and session, 2026-10-25

The [desktop/session record](winlogon-desktop-session.md) supersedes the
sections below for the current Winlogon. Native build 10, SHA-256
`e3a9cdca26ab7af5ae5b225d647c94be0dc34aa4f7428e025ddf3b3c3becdf93`, installed as
the only change in fresh overlays of the verified engineering images:

| Area | KVM 1 vCPU | KVM 2 vCPUs | TCG 1 vCPU |
| --- | --- | --- | --- |
| Boot, MSGINA, LSA rejects a wrong password | Observed | Observed | Observed |
| Licensing admission through installed `licdll` agent (activated) | Observed | Observed | Observed |
| Explorer/Luna desktop with verified token, LUID and image | Observed | Observed | Observed |
| File, HKCU, loopback, driver, SCM, Start menu, folder, Luna probes | Pass | Pass | Pass |
| Lock (`Win+L`), unlock, Windows Security, Task Manager | Pass | Pass | Pass |
| Explorer crash → re-admission → restart | Pass | Pass | Pass |
| Logoff, no user processes left, re-logon | Pass | Pass | Pass |
| RTL8139 DHCP/DNS/TCP/HTTP in the isolated namespace | 17/17 | 17/17 | 17/17 |
| Desktop Turn Off → guest-requested shutdown | Observed | Observed | Observed |
| Desktop Restart → guest reset → reboot → re-logon | Observed | Not run | Not run |

Not supported or not verified with this Winlogon: the Welcome screen (classic
logon only), Fast User Switching, Terminal Services session state (console shows
`Conn` without a user), Task Manager's Users tab data, event sounds, Group Policy
processing, domain logon, activation reminders/wizard, and themed logon-desktop
controls. After a logoff, MSGINA's edit fields did not paint (and did not
accept typing) on alternate account switches; fixed in source on 2026-11-17
(missing comctl32 `ICC_WINLOGON_REINIT` after the logoff's atom purge,
[account-switch fix](winlogon-account-switch-paint.md)). The accepted 8.1 and
8.2 images still carry the unfixed Winlogon `e3a9cdca…`. The engineering image
`XP25-Winlogon-Fix-8.2` (`fe633d15…`) carries the fix: two-account oracle 9/9 on
one-vCPU KVM, and two logoffs observed painted in the
[XP25-Winlogon-Fix VM](virt-manager-xp25-winlogon-fix.md). Since 2026-11-19 that
VM runs the Milestone 8.4 Winlogon `289abb03…`, on its own disk with only
`winlogon.exe` replaced (`XP25-Winlogon-M84.qcow2`, `471e1b06…`). Two-account oracle 9/9
on that image, one-vCPU KVM. Two logoffs observed painted in the VM.

## Winlogon policy/session continuation, 2026-10-24

The [policy/session record](winlogon-policy-session-contract.md) supersedes
older prototype results for current Winlogon. Fresh native executable SHA-256
`120a9ddebcf610a060a8aac6d42ee01f9308e1deb8b34560f26e8d230b7030d1`
is i386 PE32/5.1, 34,816 bytes, checksum `0x1091e`; all direct guest imports
resolve. The real kernel key-protection service is implemented and exercised.
Complete licensing admission still returns local error 120; it is not a
licence-server denial and no activation success is fabricated.

| Current fresh replacement gate | KVM one vCPU | KVM two vCPUs | TCG one vCPU |
| --- | --- | --- | --- |
| Native boot, MSGINA, real key-protection initialization | Observed | Observed, source MP kernel/HAL | Observed |
| Incorrect/correct credentials, profile hive and environment | Observed | Observed | Observed |
| Repeated pre-shell initialization/cleanup, cleared live ownership | Observed | Observed | Observed |
| GINA shell / source Explorer / Luna / Default desktop | Blocked by policy 120 | Blocked by policy 120 | Blocked by policy 120 |
| GINA signed-out power-off | Actual guest shutdown event | Actual guest shutdown event | Actual guest shutdown event |
| GINA signed-out restart | Not run | Guest reset and MSGINA return | Not run |
| Native desktop lock/unlock/logoff, secure-desktop attacks, full regressions | Not reached | Not reached | Not reached |
| New accepted standalone image | Not produced | Not produced | Not produced |

The separate session executable runs 31 scenarios/528 assertions in native XP
and under host sanitizers; all 40 host tests pass, including rejection of test
mode in production compilation. Its explicit doubles exercise policy gating,
shell invocation, environment ownership, desktop errors, notifications and
lifecycle/failure transitions; they do not establish native post-shell behavior.
The authenticated original-Winlogon control separately passes actual token,
UserEnv, file/HKCU, Explorer/Luna/Start/folder, network and service probes and
normal shutdown. Its read-only WMI observation reports ActivationRequired=0;
this is not substituted for a complete Winlogon policy decision. Shell crash
recovery and full replacement lifecycle/security compatibility remain incomplete.

## Previous fresh Winlogon runtime verification, 2026-10-24

The [fresh verification record](winlogon-runtime-verification.md) documents
the preceding source checkpoint. Exact input `68f098042`
fails native compilation; no executable or runtime result is attributed to it.
The corrected fresh executable is i386/5.1, 31,232 bytes, SHA-256
`d0b9c70d4e3937e575be21bb0d55b4267cec7719d5fba083c556b76f817ea815`.
It is installed as the only component change in an overlay of the latest
hash-verified standalone engineering image, retaining original recovery bytes.

| Gate, fresh corrected binary | Single-vCPU KVM | Two-vCPU KVM / TCG |
| --- | --- | --- |
| Native compile/link, direct PE dependency checks | Pass in native XP build VM | Same executable; no separate build claim |
| MSGINA UI; actual LSA incorrect/correct credential results | Observed, two pairs | Not run for this revision |
| Token, SID hive, environment preparation and cleanup | Observed, two cycles | Not run for this revision |
| Admission call stack and cleared ownership readback | Captured | Not run for this revision |
| GINA shell callback / Explorer / Default / Luna | Not reached: policy error 120 | Desktop prerequisite not met |
| Full desktop, application, file/registry/network/service regression | Not reached | Desktop prerequisite not met |
| Complete session lifecycle / normal shutdown / new engineering image | Not reached / not produced | Not reached / not produced |

Error 120 is the host's explicit unimplemented activation-orchestration boundary,
not a result from a licensing server. Real SYSKEY authentication is restored;
no fabricated licensing/authentication success is accepted. The new shell code
has compiled but has not executed past that boundary. This is not a replacement
desktop compatibility pass. The accepted original-Winlogon engineering image,
all reference sources/images and user VMs remain preserved. All 38 host checks
pass independently of the unexecuted shell path.

## Independent Winlogon prototype, 2026-10-24

The [session recovery continuation](winlogon-session-recovery.md) supersedes
the earlier profile-only checkpoint below. Native build 02, SHA-256
`2fc1ea1a801362db4e608becc52531ddbd7874ed530ea293e6b7fe9e9e1dbf55`,
merges GINA's environment and handles failed initialization without losing
owned resources or making authentication/activation errors succeed.

| Latest replacement gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Two authentication / SID-hive / GINA-environment / cleanup cycles | Observed | Observed | Observed |
| Secure error-120 rollback, authentication retry and CAD reentry | Observed | Observed | Observed |
| Wrong password rejected after initialization rollback | Observed | Observed | Observed |
| Cleared host token/profile/environment/GINA ownership, live read-only capture | Observed | Observed | Observed |
| GINA shell activation, source Explorer/Luna and desktop transition | Blocked at error 120 | Blocked at error 120 | Blocked at error 120 |
| Complete lock/logoff/power, hostile-user restrictions and desktop regression | Not reached | Not reached | Not reached |
| New standalone engineering image | Not produced | Not produced | Not produced |

This verifies recovery **before** shell admission. It does not establish normal
logoff, user-process ownership, persistent volatile-environment/GPO integration,
shell recovery, full notification/error fault paths or normal guest shutdown.
The first matrix is rejected after joining CSC's intentionally persistent
Startup worker; the corrected user join retains that worker. All experimental
disks are private overlays, with host stops distinguished from guest shutdown.
All 38 host checks pass; reference images and all 277,863 source files are
hash-preserved. The previously verified original-Winlogon image remains current.

The dedicated [licensing/activation investigation](winlogon-activation-investigation.md)
records the static evidence and every currently unresolved interface. It does
not claim activation compatibility or Windows-level activation success.

The [profile-stage continuation](native-winlogon.md) supersedes build 09's
pre-profile boundary below. Build 03 of that continuation, SHA-256
`8a90fca41f1d21454ddb224276b33afdeab60f1b39d3f5deb6bd5057a4e8d7a7`,
loads a fresh local profile, verifies the actual SID hive and user environment,
and successfully releases environment/profile resources under KVM, MP KVM and
TCG. It then rejects startup at the unresolved activation-policy boundary,
error 120. GINA shell activation, Explorer/Luna login and the session/power
lifecycle remain unverified and unfinished. No fabricated activation results
or new accepted engineering image are introduced. Original-host controls pass
two complete suites and shutdown separately; all 38 host checks pass.

This [experimental host](native-winlogon.md) is not the Winlogon used by the
accepted engineering image or the user's interactive VMs. All boot replacements
are isolated disposable overlays. Build 09's SHA-256 is
`9d3dc1b87b79c3121bafbfced1bcc9395169106fe3bece0531abcc0d08181be9`.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Original kernel, USER registration, secure desktops, real LSASS startup-key validation | Observed | Observed | Observed |
| SAM ready, trusted LSA, original MSGINA 1.4 and graphical login dialog | Observed | Observed | Observed |
| Incorrect password rejection and SAS interruption without a shell | Observed | Observed | Observed |
| Valid GINA result and returned primary-token/LUID/session/logon-SID checks | Observed | Observed | Observed |
| Debugger capture of actual LSA success status | Captured | Incomplete trace | Captured |
| Profile, Explorer/Luna and complete login | Blocked at error 120 | Blocked at error 120 | Blocked at error 120 |
| Lock/unlock, logoff/relogin, secure-user denial, networking/app/service full regression, normal shutdown/restart | Not reached | Not reached | Not reached |
| Independent standalone engineering image | Not produced | Not produced | Not produced |

The missing licensing/activation orchestration is an explicit session boundary;
full shell/lifecycle code also remains unimplemented. The prototype
does not fake security success or suppress exceptions. Stored SYSKEY mode only,
classic MSGINA UI and local console authentication are covered so far.
Host state-machine/decoder tests pass; original-host process-only controls and
offline rollback recovery pass existing suites and real shutdown separately.
They do not establish replacement compatibility or security equivalence. The
older verified Explorer/UserEnv matrix below remains the accepted desktop.

## Native Explorer and UserEnv, 2026-10-24

The [integration record](native-explorer-userenv.md) supersedes the earlier
failed variants below. All tests use disposable isolated guests with the prior
native kernel, SCM/SMSS/Regsvc/MSGINA, networking and XP25 branding preserved.

| Tested stack / gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Corrected original Explorer alone | Pass | Pass | Pass |
| Corrected original UserEnv alone | Pass | Pass | Pass |
| Both components together | Pass | Pass | Pass |
| Login/logout, lock/unlock, Explorer/Start/Luna, folder/file operations | Pass | Pass | Pass |
| Fresh profile initialization, hive/registry operations, unload/delete | Pass | Pass | Pass |
| Prior service, TCP/UDP, DHCP/DNS/isolated HTTP, Win32/MSI and branding fixtures | Pass | Pass | Pass |
| Actual mapped binaries, original recovery, Notepad readback, normal shutdown | Pass | Pass | Pass |
| Additional cold boot from standalone engineering QCOW2, two full suites and shutdown | Pass | Not repeated | Not repeated |

Explorer uses one corrected SP3 SHLWAPI provider call. UserEnv rebinds four
private ordinals; original implementation bytes remain unchanged. Three missing
implementations (CheckXForestLogon, CreateURLFile, DeleteURLFile) still use the
retained original SP3 dependency. No Winlogon patch, exception suppression or
success-returning security stub is introduced. Captured NT 5.1/x86/2600/SP3,
product/licensing identity remains unchanged. These local-account and fixture
tests do not establish domain/GPO/cross-forest/roaming-profile, every private
shell ABI, arbitrary legacy software or sustained security/stability equivalence.
Source completeness and a clean Windows Setup ISO remain separate work.

## Historical Regsvc and MSGINA extensions, 2026-10-23

The UserEnv/Explorer failures below describe preserved earlier variants; see
the 2026-10-24 matrix above for the corrected accepted artifacts.

The [extension record](native-component-extensions.md) covers individual changes
on the branded original-kernel/SCM/SMSS desktop. Working reference images and user
VMs are not integration targets.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Original Regsvc: existing 54 regressions, 21 RPC/lifecycle cases, branding and installer fixtures | Pass | Pass | Pass |
| Original Regsvc: actual mapped checksum, exact retained DLL and original recovery | Pass | Pass | Pass |
| Original Regsvc: logoff/re-entry, Explorer/Luna, Notepad and fresh service/guest shutdown | Pass | Pass | Pass |
| Subsequent original MSGINA: same full suite and four GINA/host cases | Pass | Pass | Pass |
| Original MSGINA: incorrect password rejected, existing local login succeeds, lock/unlock | Pass | Pass | Pass |
| Original MSGINA: live Winlogon-mapped DLL, secure-desktop write denial, Notepad, normal shutdown | Pass | Pass | Pass |
| UserEnv SP3 export adapter as boot replacement | Fail: Winlogon AV | Fail: Winlogon AV | Fail: Winlogon AV |
| Original Explorer shell integration | Fail: Explorer crash | Not attempted | Not attempted |

Regsvc testing uses real local named-pipe RPC with stopped-server negative
controls. SMB/remote network RPC is unverified; the first installed-SP3 control
returned error 53 for the SMB path. GINA evidence covers the existing local XP25
account, not domain, smart-card, FUS, RDP or broad security equivalence.

Original Explorer compiles successfully with original import/support libraries;
static direct/delay import presence passes but does not establish runtime private
shell ABI compatibility. The UserEnv adapter preserves original native code and
pins all SP3 ordinals, forwarding CheckXForestLogon and two unknown private bodies
to unchanged SP3 UserEnv. Fifteen ABI/profile checks pass when loaded from a
readonly CD in an own user process, separate from Winlogon. This is neither
independent implementation of those three functions nor boot compatibility.
Both rejected candidates remain excluded from the accepted engineering disk.

The packaged disk retains installed UserEnv, Explorer, Winlogon and other original
Microsoft dependencies. It is a private preinstalled engineering image containing
source/build payload, not a clean licensed installation or Windows Setup ISO.
Media/license entitlement and complete source/binary accounting remain pending.

## Interactive anniversary VM, 2026-10-23

`XP25-Anniversary` is a separate persistent `qemu:///system` domain, using a
flattened, preboot sector-identical copy of the newest branded desktop,
`brand-final-tcg-01` (reference SHA-256
`d4fa9505a725fcc670ddfd443d4179e5871ef32d27d8073e6e7e04f6b4774f85`).
The original one-vCPU qemu32/512 MiB/i440fx/IDE/VGA/RTL8139 profile boots under
KVM with the same original UP kernel/HAL, SCM/SMSS and native networking helper.
The loopback VNC console opens through virt-manager. All 54 established and 17
branding observations pass, alongside Win32/MSI fixtures and service/guest
shutdown. Sixteen critical files and captured compatibility identity values
match the reference after shutdown. Clone MAC `52:54:00:25:00:03` receives
`10.25.0.11` from the existing isolated libvirt network; DNS, TCP/UDP and isolated
HTTP pass. Only this additional DHCP reservation changes shared configuration.
Reference images and pre-existing guests remain preserved. The VM is left shut
off, ready for interactive startup; no broader compatibility claim is made.
[Exact commands, evidence and limitations](virt-manager-xp25-anniversary.md)

## XP25 resource branding, 2026-10-23

The [branding record](branding.md) covers separate disposable children of the
native SCM/SMSS checkpoint. System/About resources, Explorer, Shell32 and
LogonUI are integrated in separate stages; boot-critical components are not
replaced together. No kernel code, VERSIONINFO, ABI, licensing mechanism or OS
ProductName changes are made. One reviewed per-profile localized-name cache
entry is backed up and refreshed for the modern Start menu.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Source-kernel boot, native SCM/SMSS, Explorer/Luna | Pass | Pass | Pass |
| Existing 54 standard/pointer/session/network/service observations | Pass | Pass | Pass |
| NT 5.1/x86/2600/SP3/product type/API reporting and captured identity match control | Pass | Pass | Pass |
| Branding resources and original recovery files retained | Pass | Pass | Pass |
| Logoff, branded chooser and successful reauthentication | Pass | Pass | Pass |
| Calculator arithmetic and unique Notepad save/readback | Pass | Pass | Pass |
| Own Win32 install/run/uninstall and registry-only MSI install/uninstall fixtures | Pass | Pass | Pass |
| DHCP, DNS, TCP/UDP, isolated HTTP and normal shutdown | Pass | Pass | Pass |

System Properties/About layouts and login header are visually reviewed at the
recorded 640x480/default-font layout; simulated 96/120/144-DPI font measurements
pass. Actual high-DPI desktops, other languages, classic-menu rendering, broad
third-party installer/application coverage and original signature/catalog trust
are not established. Modified UI hashes invalidate any original signed-file
identity; no trust or WFP bypass is introduced. The test fixtures do not establish
general compatibility. The existing `XP25-Desktop` remains unmodified.

## Milestone 3 original SCM and SMSS, 2026-10-23

The [component reconstruction record](native-components-milestone.md) establishes
these results on separate disposable children of the Milestone 2 images.
Only SCM was first replaced. SMSS was subsequently replaced alone on each frozen,
verified SCM guest. Regsvc, Msgina and UserEnv were then only compiled candidates;
the later extension results above supersede that status.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Native SCM: source-kernel identity / Explorer-Luna | Pass | Pass | Pass |
| Native SCM: standard / pointer / session / networking probes | Pass | Pass | Pass |
| Native SCM: service creation, dependency startup, stop rejection, stop/restart, deletion | Pass | Pass | Pass |
| Native SCM: live mapped checksum / retained binary / original recovery copy | Pass | Pass | Pass |
| Native SCM: logoff/login and Notepad save | Pass | Pass | Pass |
| Native SCM: service shutdown notification / normal guest shutdown | Pass | Pass | Pass |
| Subsequent native SMSS: full regression and service suite | Pass | Pass | Pass |
| Subsequent native SMSS: logoff/login, Notepad, service and guest shutdown | Pass | Pass | Pass |

An installed-SP3-SCM control guest passes the same fourteen service observations
and shutdown fixture. All SCM direct and delay imports resolve by export presence
against the extracted guest modules; both SCM executables have no exports.
This does not establish complete SP3 behavior/security equivalence, remote RPC,
domain-account services, all recovery policies, driver-service transitions or
sustained-load stability. UserEnv was not promoted. The later exact export audit
corrects the ordinal-only interpretation: 207–209 are existing named bodies at
shifted ordinals; missing implementations are CheckXForestLogon and private
200/201. The subsequent adapter still fails boot integration.
Games, accelerated graphics, TLS, IPv6 and additional hardware remain unverified.

## Interactive libvirt desktop, 2026-10-23

`XP25-Desktop` is a persistent `qemu:///system` domain with a loopback VNC
console. Its independent disposable disk was verified sector-identical to
`network-native-kvm-mp-02`, SHA-256
`96ae34bf4c66cb79a1211c6c29e4cf2e48dde99697ed00efe8ce4588657b1940`,
before boot. No reference backing disks are attached. The retained two-vCPU KVM,
qemu32, 512 MiB, i440fx 8.2, IDE, standard VGA and RTL8139 configuration reaches
Explorer/Luna. Six standard, eleven pointer, six session and seventeen network
observations pass; DHCP/DNS and a temporary isolated HTTP fixture were exercised.
A guest-requested shutdown is recorded. This VM is left shut off for interactive
startup; its registration does not broaden the existing hardware, application,
graphics or Internet support claims. On 2026-10-25 the domain and its disk were
removed through virt-manager's Delete wizard; the evidence directory remains.
[Exact settings, image hashes and evidence](virt-manager-xp25-desktop.md)

## Milestone 2 networking, 2026-10-23

The [native networking record](native-networking-milestone.md) establishes these
results on fresh source-kernel clones, separately from the historical SP3
installation tests below. Evidence is under `.work/boot-debug-20261022/`.

| Gate | KVM, one vCPU | KVM, two vCPUs | TCG, one vCPU |
| --- | --- | --- | --- |
| Source-kernel boot / Explorer-Luna session | Pass | Pass, source MP kernel/HAL | Pass |
| File / registry / pointer regressions | Pass | Pass | Pass |
| Notepad save/reopen | Pass | Pass | Pass |
| IPv4 address/port parsing and invalid-octet rejection | Pass | Pass | Pass |
| TCP and UDP loopback payloads | Pass | Pass | Pass |
| QEMU RTL8139 / original installed NDIS driver | Pass | Pass | Pass |
| DHCP lease `10.25.0.10/24` from `10.25.0.1` | Pass | Pass | Pass |
| Controlled DNS `xp25.test` | Pass | Pass | Pass |
| Isolated TCP/HTTP server | Pass | Pass | Pass |
| Normal guest shutdown / disk check | Pass | Pass | Pass |

KVM also passes explicit interactive authentication (LsaLogonUser zero status /
substatus, matching Explorer/user logon ID), a cold-boot child, and an independent
native-helper build followed by ten network runs, a guest warm reboot and full
probe suite. These are short regression checks. TLS, Internet access, IPv6,
VirtIO, VMware, EC2 and sustained-load/security testing remain unverified.

Only source-built `wshtcpip.dll` was added to the established guest component
set. The original installed Microsoft AFD/TCPIP/NDIS, DHCP/DNS and SCM remain.
The SP3 helper's `RtlIpv4StringToAddressExW` and `RtlIpv4AddressToStringExW`
imports remain incompatible with native ntdll; eight extended IPv4/IPv6 A/W
exports remain absent. The tested original helper uses existing native APIs.
Native Ws2_32 lacks GetAddrInfoW, FreeAddrInfoW and GetNameInfoW; applications
requiring those Unicode resolver APIs remain unverified.
The preserved Milestone 2 image hashes and all per-run commands/results are
linked in the networking record.

The [supplied XP SP3 guest](xp-sp3-guest.md) has booted in KVM. Its stopped
backing-disk SHA-256 is
`e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c`.
Results below apply to that guest and its recorded build overlay, with QEMU
8.2, i440fx, qemu32, one CPU, 512 MiB RAM, IDE and standard VGA. They do not
establish a custom source build or other hardware configurations.

## Supplied SP3 runtime regression coverage

| Requirement | Implemented observation | Current execution status |
| --- | --- | --- |
| Kernel boot | QEMU screenshots and guest identity | Supplied XP SP3 boots; source-kernel results are recorded separately below |
| User login | Manual logoff, account chooser, XP25 logon and post-logon probe | Observed once; automated transition test not implemented |
| Explorer | Check shell PID resolves to `explorer.exe` | Pass under Administrator and XP25, including overlay reboot |
| Registry | Volatile HKCU DWORD roundtrip with cleanup | Pass in recorded guest runs |
| Filesystem | Temporary file write/read/cleanup | Pass in recorded guest runs |
| Networking | Bounded IPv4 UDP loopback roundtrip | Pass; no NIC/DNS/TLS test |
| Legacy Win32 applications/games | Application fixtures not supplied | Not tested |
| Driver initialization | Enumerate active kernel driver services | Corrected probe passes: 70 running services, two pages; individual device functionality untested |
| Shutdown | Manual ACPI request and QMP shutdown event | Observed from working desktop; earlier Cirrus first-boot attempt timed out |
| Security regressions | Runtime dependency gate for probe | No guest mitigation/security validation |

`tests/guest/xp_probe.c` reports six implemented observations separately from four
explicitly untested areas. Its exit 0 must not be interpreted as passing this
entire table. [Guest instructions](../tests/guest/README.md)
The original probe failed with `ERROR_MORE_DATA` (234). The corrected probe and
retained failure are documented in [the guest record](xp-sp3-guest.md).

Four checked x86 source kernels have also linked and passed PE inspection.
The first source-kernel selection stopped at incompatible SP3 NTFS imports.
A matching original NTFS driver then reached a checked/free HAL mismatch
(0x79). A checked original HAL also built; its KVM boot reaches the HAL APIC
priority readback assertion (0x8e, STATUS_BREAKPOINT; written 0x3d, read 0x30),
before login. These failed experiments are separate from the verified SP3
runtime. The original UP/MP/PAE target filenames all use MP-enabled checked
configuration here (`NT_UP=0`); multicore runtime had not yet been tested at that
initial checkpoint. The later two-vCPU result is recorded below.
[Native build and boot evidence](native-kernel-build.md)

## Source boot investigation, 2026-10-22

Latest result, 2026-10-23: native LSASRV/Secur32 resolves authentication, and the
tested kernel-held pointer-cookie extension resolves the missing DecodePointer
shell dependency. XP25 authentication, Explorer/Luna, filesystem/registry tests,
Notepad save/reopen and guest-requested shutdown pass under KVM. Fresh TCG and
two-vCPU KVM guests also pass pointer and interactive-session regressions.
[Exact environment, hashes and limitations](source-desktop-milestone.md)
The following paragraphs retain earlier failure evidence.

The reference `xp25-sp3` VM has the libvirt disk/RAM snapshot
`xp25-before-apic-debug-20261022`. All following experiments use disposable
overlays under `.work/boot-debug-20261022/`.

| Configuration | Recorded result |
| --- | --- |
| Original checked kernel/HAL, KVM, qemu32, one CPU | HAL `KfLowerIrql` reads TPR `0x30` after writing `0x3d`; assertion, no login |
| Same, VAPIC disabled | Same readback failure |
| Same, split IRQ chip | Same early failure |
| Userspace APIC with KVM | Host rejects configuration: `KVM does not support userspace APIC` |
| Original checked kernel/HAL, TCG, qemu32, one CPU | `SESSION5_INITIALIZATION_FAILED` (0x71); SP3 ntdll calls SP1 inline syscall bytes as pointer `0x340fd48b` |
| Rebuilt kernel with ntdll pointer ABI, corrected HAL, matching source NTFS/MountMgr, TCG | Syscall pointer is `0x7c90e520`; advances to Session Manager error `0xc0000263` (missing driver entry point); no login |
| Same corrected set, KVM | Passes original readback assertions; stops at checked fast-mutex APC_LEVEL equality check because its TPR comparison also includes the discarded nibble |

The completed HAL revision compares TPR priority classes while retaining
serialization, IRQL validation and mutex ownership checks. All seven recorded
`matrix2-*` configurations pass the earlier APIC stops and reach the SP3 GUI
dependency failure. A negative test supplying the wrong priority class still
raises bugcheck `0x9`. No source-kernel desktop is claimed.

SP3 Win32k imports `MmCommitSessionMappedView` and `SeTokenIsWriteRestricted`,
which the supplied source kernel lacks. SP3 FltMgr also imports the unexported
`RtlAddAccessAllowedAceEx`. These remain incompatible until a matching native
component or a complete, tested implementation is available. Security APIs have
not been stubbed out.

Matching source Win32k subsequently compiled and loaded; USER/GDI initialization
runs and CSRSS appears. CSRSS later exits with `STATUS_INVALID_INFO_CLASS`
(`0xc0000003`). Matching native CSRSS/CSRSRV and BaseSrv builds then succeeded.
With native WinSrv, User32 and GDI32 installed in a fresh clone, the loader
returns `STATUS_DLL_INIT_FAILED` (`0xc0000142`) while loading WinSrv. The direct
imports checked for this component set resolve. An entry-routine trace shows
SP3 Kernel32 returning FALSE on process attachment before User32 starts.
Native Kernel32 builds successfully. Source GUI syscall stubs also need the
shared-page ABI correction: the original stubs execute pointer bytes at
`0x7ffe0300`, causing an access violation at `0x7ffe0309`. Rebuilt User32/GDI32
use the original INT 2E dispatcher directly. A fresh guest records successful
Kernel32 and User32 process attachment. Relinking WinSrv removes its remaining
old stubs and advances to Winlogon, which exits with status `0x80` before login.
SP3 Framebuf imports the missing Win32k `EngBugCheckEx`; matching native Framebuf
loads and removes that error, but hardware pointer initialization fails. VGA
fallback remains unverified. The actual Winlogon loader exception is
`0xc0000139`: SP3 ntdll requests the absent `Kernel32!BaseQueryModuleData`.
Matching native ntdll built and passes this stage in a new clone, then fails on
SP3 Winsock's `RtlIpv6StringToAddressExW` dependency. The revised import checker
includes bound import rows; the earlier scans omitted those symbols.
Authentication and Explorer under the custom kernel remain unverified.
[Detailed boot investigation](boot-investigation.md)

Matching native Winsock and its helper subsequently compiled. Matching IMM32
then removes another embedded SP3 GUI syscall mismatch. Fresh KVM and TCG clones
reach the graphical XP login screen. The loaded kernel is
`\\WINDOWS\\system32\\XP25KRNL.EXE`, checksum `0x33f857`, matching the compiled
input. Authentication fails: LSASS sets unsupported token information class 16
and `LsaLogonUser` returns `0xc0000003`. Matching original LSA is being built.

| Source-kernel milestone gate | Recorded status |
| --- | --- |
| Source kernel loads | XP25KRNL.EXE path and compiled checksum `0x33bcdb` verified live under KVM/TCG; matching MP kernel also verified |
| Graphical login screen | Observed in fresh KVM and TCG clones |
| Authentication | Native LsaLogonUser status/substatus 0; logon ID matches XP25 and Explorer tokens |
| Explorer and Luna desktop | Observed under KVM, TCG and two-vCPU KVM; session probe passes |
| Filesystem and basic applications after login | KVM temporary-file and HKCU round trips pass; Notepad save/reopen verified offline |
| Normal source-guest shutdown from desktop | Guest `shutdown.exe -s -t 0` reaches QMP shutdown state |
| Linux-host reproduction | Fresh clones launched from the Linux host; native build-media pipeline executes independently |
| Pointer compatibility/security contract | Eleven checks pass, including 262,144 concurrent round trips and rejected remote/invalid queries; not a general security audit |
| Networking | Historical SP3-helper failure 10022; resolved by the original source-built helper in Milestone 2 above |

Clean rebuilding also exposes absent executive files `exinit.c` and `systime.c`.
Native kernel links use the four supplied i386 prebuilt objects, whose hashes
are recorded in `build-04/prebuilt-inputs.json`; a full rebuild from C/ASM and a
free-build variant are not established.

## Software targets

No specific modern application release has been selected or installed. A target
family does not imply all releases or architectures are feasible.

| Target | Installation | Launch | Functionality | Stability |
| --- | --- | --- | --- | --- |
| Supplied Explorer/Luna | Installed from supplied SP3 ISO | Desktop and shell observed | Basic 640×480 desktop and CD browsing observed | Several sessions; no sustained stability test |
| Control Panel | Present in installed guest | Not tested | Not tested | Not tested |
| Supplied Notepad | Installed from SP3 ISO | Observed | Edit/save/reopen roundtrip; extracted text matches | One short check |
| XP-era DirectDraw/Direct3D games | Not tested | Not tested | Not tested | Not tested |
| Legacy Win32 installers/applications | Not tested | Not tested | Not tested | Not tested |
| Python 3 | Not tested | Not tested | Not tested | Not tested |
| Git | Not tested | Not tested | Not tested | Not tested |
| Current TLS client | Not tested | Not tested | Not tested | Not tested |
| Chromium-based browser | Not tested | Not tested | Not tested | Not tested |
| Newer C/C++ runtime | Not tested | Not tested | Not tested | Not tested |
| .NET application/runtime | Not tested | Not tested | Not tested | Not tested |
| Contemporary developer utility | Not tested | Not tested | Not tested | Not tested |
| One-Core-derived API-set aliases | Not installed | Not tested | 28/arch statically checked | Not tested |

## Hardware and deployment targets

| Target | Verified evidence | Guest support status |
| --- | --- | --- |
| QEMU i440fx 8.2, BIOS, IDE, standard VGA, KVM via libvirt | Supplied XP guest registered in VMM; console screenshot at 640×480; no network interface | Basic desktop observed; accelerated graphics unverified |
| QEMU Cirrus | Text/GUI Setup works; first-boot resolution transition repeatedly blacks out | Desktop transition failed; checkpoint retained |
| Multicore/SMP/modern CPU instructions | Existing source paths only | No new support claim |
| UEFI/GPT/NVMe/AHCI/USB 3.x | No guest experiments | Unverified |
| Modern ACPI/interrupt controllers | Existing ACPI/HAL code only | Unverified |
| Modern GPU/multiple displays/passthrough | Host VFIO node exists | No device or driver validated |
| QEMU RTL8139 Ethernet | Source-kernel KVM UP/MP and TCG: DHCP, DNS, TCP/UDP, isolated HTTP | Verified only in the recorded configurations; see Milestone 2 |
| Other Ethernet/Wi-Fi/IPv6/Bluetooth | No corresponding device/runtime tests | Unverified |
| EC2 | XP omitted from supported import list; i386 imports discontinued | Blocked, no deployment |

EC2 constraints were checked against [AWS import requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html).
Do not mark a target supported based on a source symbol, an API stub, a successful
link, a firmware screen or a device node alone.
