# Milestone 7: browser integration and IE dependency audit

Worktree/branch: `xp25-browser`, based on `xp25-ai` at `26dd86f0f`.
Private evidence: `.work/browser-20261025/` in that worktree (`W`).
The frozen input is the accepted AI engineering image, SHA-256
`ec22f45b67af19f584eb6ca0a286e943731298543aa1b910eab6ff42674bee2a`.
It includes the source NT 5.1 x86 kernel, native Explorer/UserEnv and the existing
ClippyAI/RoverAI stack, with the original Winlogon. The separate independent
Winlogon and registered user VMs are outside this experiment.

**Current status: installation and browser tests implemented; full native
KVM/TCG acceptance is blocked by browser failures; a standalone experimental image has been generated.**
Underlying IE compatibility DLLs remain. A complete Trident removal is not
claimed.

## Package and provenance

The latest stable official release identified on 2026-10-25 is
[Supermium 150.0.7871.255 R2.01](https://github.com/win32ss/supermium/releases/tag/v150-r2.01),
published 2026-10-21. The official x86 portable asset is
`supermium_150_32_nonsetup.zip`, 165,223,567 bytes, SHA-256:

```
d9a06a6cea97e41bfa9b9595481f9728fbfd35ea0fcc0f67ad6f4a9431c843b3
```

The downloaded file matches the official GitHub release-asset digest. The raw
release JSON, archive, extracted file hashes and PE import audit remain in
`W/acquisition/`. All 43 browser PE files in the inspected package are x86;
no missing direct symbol was found among the then-extracted XP25 system DLLs
and the package's own DLLs. This static observation excludes unobserved dynamic
lookups and behavioral contracts.

A fallback [144.0.7559.256 R5](https://github.com/win32ss/supermium/releases/tag/v144-r5)
was also downloaded, verified and actually launched in a separate guest.
Its archive is 153,211,908 bytes, SHA-256
`17acfcdf89ea651905053b50b0fce5a28db19cb2c69ed5579c7b177806ed6d31`.
It is a diagnostic fallback, not the selected final package. The earlier
keyboard-driven observations were inconclusive; a captured source-kernel
idle loop and advancing guest clock do not establish a kernel assertion or
crash. The fallback guest also executed the first native utility build.

The older complete source tree's Chromium BSD license permits redistribution
subject to retaining notices/disclaimers and avoiding endorsement claims.
The 150 release tag contains patches and does not provide a top-level LICENSE;
the package also bundles compatibility and third-party DLLs. Full binary-bundle
redistribution rights and notice completeness have **not** been established.
The original archives are retained privately, and no browser/Microsoft binary
is committed or uploaded. `redistribution_approved` remains false. The older
license is retained as a clearly named reference, not as proof that it covers
every 150 binary. `chrome://credits` remains the browser's built-in notices UI.

## Implemented integration

- `build/prepare_browser.py` verifies exact bytes/SHA-256 before extraction,
  rejects archive traversal, duplicate paths and symlinks, and creates private
  media with a file-integrity manifest. Portable convenience `.cmd` launchers
  that include credential-encryption disabling options are excluded from
  installed entry points; the verified original archive remains unchanged.
- `build/browser_config.py` generates NT 5.1 registration and installation/
  rollback commands. Machine and XP25-user HTTP/HTTPS, HTM/HTML and `.url`
  registrations point at Supermium or the new native Internet-shortcut adapter.
  Legacy `htmlfile`/`htmfile` browser verbs are retargeted and stale browser DDE
  registrations are removed. Normal file/folder and `.lnk` associations stay
  with the native shell.
- `components/browser/browserctl.c` creates desktop, Programs and Quick Launch
  shell links using native COM and Supermium's own executable icon. It parses
  Internet shortcuts without JScript/VBScript, accepts HTTP/HTTPS only and
  rejects control characters, quotes and other schemes. Other `.url` schemes
  are an explicit compatibility limitation.
- The XP Internet desktop icon is hidden, Active Desktop is disabled for the
  installed user, the default Internet Start-menu client becomes Supermium,
  the IE browser client registration and known English IE shortcuts are hidden.
  IE executable files, COM automation and shared DLLs remain for compatibility.
  Deliberately invoking an original IE executable/COM class is not intercepted.
- The native utility snapshots changed registry trees, including absent-key
  state, before applying registration. It preserves existing Supermium links
  and removed IE links for development rollback. Rollback restores the recorded
  trees and links; use it before unrelated changes to those trees. Application
  files/profile data are retained. It is not a general-purpose uninstaller.
- Classic omnibox/compact UI, `SupermiumCustomTabs` and `ForceXpTheme` complement
  Luna. The verified standard-VGA engineering profile selects software rendering
  through a machine DWORD and `--disable-gpu`. Other hardware remains untested.
  No browser sandbox/certificate/security bypass is added to launch commands.

The original NT compiler built all six current utilities with `/W4 /WX` in disposable
AI-image overlays. Build 05 supplies the current integration executable;
`W/native-05/collect.json` pins exact native binary hashes, staged sources and sizes. Host
cross-compilation remains a separate, independently import-checked path.
No Microsoft core component or reference source file is changed in this
milestone.

## Actual browser evidence so far

`W/runs/browser-150-soft-up-02` is a preliminary software-rendering run, followed
by the final native matrix under `W/matrix-01` / `W/runs/browser-final-01-*`.

The preliminary run passes 13 shell-registration/shortcut/NT-version checks.
Its `cdp-03/result.json` records local HTML, modern JavaScript (optional chaining,
async/Promises, BigInt, Map/Set, WebAssembly, local storage), multiple tabs and a
completed download. The downloaded fixture's independently extracted SHA-256 is
`1d94b07c8028c3b4e886301ea0373116da9c4b0ed4f9ac58950308ce65eb9cc2`.
After `Browser.close`, the recorded module/process inventory contains no
`chrome.exe` or `iexplore.exe`.

The same browser negotiated TLS 1.3 / CHACHA20_POLY1305 with `example.com`, with
subject/SAN `example.com` and issuer `Cloudflare TLS Issuing ECC CA 3`. It rejects:

| Negative case | Observed browser result |
| --- | --- |
| Expired certificate | `ERR_CERT_DATE_INVALID` |
| Wrong hostname | `ERR_CERT_COMMON_NAME_INVALID` |
| Untrusted self-signed certificate | `ERR_CERT_AUTHORITY_INVALID` |

No certificate verification bypass, certificate import or error-page exception
was used. This does not establish every site's compatibility, revocation or
certificate-transparency behavior.

Initial normal-rendering tests reached a page but also showed browser child
process failures. Software rendering was tested because the standard VGA guest
has no verified D3D acceleration. The first automated run also exposed a
30-second idle timeout in the test-only DevTools bridge; a WebSocket keepalive
fixed the harness interruption. A later multi-hour gap let the bounded bridge
expire as designed; that connection refusal is not browser-exit evidence.

The first broad-regression attempt retained two fixture failures: omitted MSI
data subdirectories, and the AI probe running outside its expected guest path.
The final media copies both correctly. These failures are not silently counted
as operating-system or browser passes.

## Sandbox and network boundary

Supermium 150 internally adds `--no-sandbox` on this NT 5.1 configuration;
XP25's supplied launch commands do not request it. Sampled browser child tokens
are unrestricted. Binary inspection shows an OS-version branch appending the
switch, and upstream source also has older-Windows sandbox exceptions.
**A working browser sandbox is not established here.** Separate processes and
job membership are not proof of security isolation. No sandbox weakening patch
or replacement security API is installed to obtain a pass. This is a material
security limitation of the current browser/OS combination.

Every test VM has a fresh writable overlay, distinct name/MAC and private QMP
UNIX socket. No VNC/TCP management listener is opened. A fresh network namespace
has no public uplink/default route and IPv4 forwarding is disabled. An optional
host-controlled CONNECT proxy permits only the exact recorded test names on
port 443, resolves them on the host, rejects non-global addresses and tunnels
TLS unchanged. All other destinations are denied. It exposes no guest SMB,
RDP or other service to the public Internet. Host gateway sockets are private.
Supermium does not make the underlying XP system generally secure.

DevTools, its fixed-address native bridge, test profiles, dummy provider keys
and proxy configuration are test fixtures; they do not belong in the standalone
installation image. The browser utility records process/module/memory metadata,
not browser history, cookies, passwords, session tokens or live user URLs.
Only newly created fixture profiles are driven through DevTools.

## IE inventory and replacement boundary

`build/audit_ie.py` writes private PE, source-reference and loaded-module graphs.
The installed-image sample contains 1,637 parsed PE files and 10,981 direct/delay
import edges. Its 55 parse failures include DOS/16-bit compatibility binaries
and are retained; they are not silently treated as dependency-free.
The source search has 14,723 matches, including headers/comments/dead paths;
those are investigation leads, not proof of runtime dependence.

| DLL | Static consumers in the sample | Disposition |
| --- | ---: | --- |
| `mshtml.dll` | 3 | Retained; HTML Help/Help and Support, WebBrowser and legacy COM contracts need separate tests/replacement |
| `shdocvw.dll` | 8 | Retained; native Explorer imports it and Shell32/BrowseUI use it |
| `browseui.dll` | 3 | Retained; native Explorer's navigation infrastructure |
| `urlmon.dll` | 70 | Retained; shell, Help, downloads/monikers and third-party contracts |
| `wininet.dll` | 91 | Retained; OS/services and Win32 networking consumers, not simply the IE browser |
| `jscript.dll` | 0 direct | Retained; COM/dynamic consumers are not ruled out by zero imports |
| `vbscript.dll` | 0 direct | Retained; dynamic scripting and installer compatibility require separate analysis |
| `ieframe.dll` | 7 | Present and retained; includes Internet Options, URL handler and shared HTML consumers |

The live source-built Explorer sample loads BrowseUI, Shdocvw, URLMon, WinINet
and IEFrame while ordinary shell operations continue. It did not load MSHTML
in that sample. This does not prove that every desktop/help/control-panel path
is Trident-free. Help and Support, HTML Help, Internet Options, scripting hosts,
installed services, third-party apps and dynamic COM activation require their
own runtime evidence before a DLL can be removed.

The new `.url` handler replaces the normal web-launch route with native Win32
code. It does not implement `IWebBrowser2`, `IHTMLDocument*`, OLE document hosting,
script dispatch or MSHTML editing. Chromium cannot be substituted for those
COM classes by changing DLL names. No general HTML COM adapter, BrowseUI rewrite,
WinINet/URLMon replacement or scripting-engine deletion is claimed. A networking
replacement would need calling-convention, ordinal, proxy, cache, callback,
error and COM-moniker compatibility tests. Browser TLS results do not upgrade
WinINet/SChannel for other applications.

## ClippyAI and RoverAI

The five existing native AI binaries stay unchanged. Browser installation
publishes only version/release/package hash/path/update policy under
`HKLM\SOFTWARE\XP25\Browser`, already readable through ClippyAI's allowlisted
`registry_read` tool. The existing process, Event Log and network diagnostics
remain available for health/error investigation. `build/check_browser_update.py`
checks only official release metadata on the modern host; it never downloads or
installs an update. Installation/update authorization is not inferred from a
metadata result. No browser-profile collection tool or silent browsing-activity
collection is introduced. Dedicated crash interpretation/approved-URL/update UI
work remains beyond this initial read-only integration.

## Reproduction and remaining acceptance

Use `build/browser_tools.py` for the recorded cross build, or
`build/prepare_browser_native.py` plus a disposable native build guest. Prepare
the official package with `build/prepare_browser.py --software-rendering`, then
add the private frozen regression fixtures with `build/browser_test_media.py`.
`vm/browser_matrix.py` runs the KVM 1-vCPU, KVM 2-vCPU and TCG cases using fresh
isolated guests. It retains browser reports, transcripts, screenshots, serial
results and actual guest-shutdown events. Installed-file verification and normal guest shutdown precede standalone packaging.
The packager marks the result experimental and unaccepted; it does not imply a
passing matrix or redistribution permission.

Pending at this documentation checkpoint: complete passing matrix, profile/settings
restart persistence, Help and Support functional navigation, HTTPS downloads,
repeatable standalone restart stability and independent boot proof. Legacy apps beyond the supplied fixtures,
physical hardware and complete removal of Trident remain unverified.


## Corrected associations, rollback and later runtime evidence (2026-10-26)

The normal default-handler diagnostic exposed a real compatibility bug with
`--single-argument`: the XP browser path preserved quotes as URL bytes, trying
to resolve a host named `"http`. The diagnostic correction used ordinary quoted Windows arguments; the current
implementation routes validated single targets through the native launcher. `browser-fixed-02-up/browser-js-results.jsonl`
contains independent page receipts for HTTP, HTML, HTM and Internet shortcuts,
all with six JavaScript checks passing. A rejected `javascript:` shortcut
returns 87. This positive page evidence replaces the earlier insufficient
ShellExecute-success-only observation. HTTPS handler registration and dispatch
are verified separately from the preliminary browser TLS tests.

`browser-rollback-01` completed installation, rejected an unknown snapshot ID
with code 2, and restored all 24 registry scopes. Eight existing exports are
byte-identical before/after; sixteen missing scopes are absent again. Twelve
known IE/Supermium shortcut paths match the original image's content/absence.
Private evidence: `rollback-extracted-01/comparison.json`,
`rollback-links-01/result.json`. The guest reached QEMU's shutdown state and
was checked/frozen normally. The first event observer timed out before that
shutdown, so it is not counted as a captured shutdown event.

`ie-audit-03` includes 216 earlier loaded-module observations plus the later
help/browser sample. Source-built Explorer loads BrowseUI, Shdocvw, URLMon,
WinINet and IEFrame. Help and Support actually loads MSHTML, JScript, URLMon,
WinINet and IEFrame. Supermium also loads Shdocvw, URLMon and WinINet in the
sample; its independent Chromium TLS implementation does not prove those
Windows APIs removable. Help process/module loading is demonstrated, but
complete Help navigation has not been verified. Removing Trident today would
break an observed system dependency; no DLL deletion is applied.

The original UP-image two-vCPU attempt bugchecked (0x7E, C0000005). The accepted
AI multiprocessor image uses a different, already source-built native NT kernel/
HAL pair. `build/browser_mp_baseline.py` creates a separate candidate changing
only `xp25krnl.exe` and `xp25hal.dll`, preserving the UP image and all other
system binaries. The candidate boots with two vCPUs and passes 13 shell checks,
but later displays a Supermium crash dialog; its DevTools test times out.
It is diagnostic evidence, not an accepted MP engineering baseline.

The fresh corrected UP run also fails a DevTools connection after target
creation; an earlier native run passed all nine browser/appearance checks but
failed its reopen test. Browser exits of -36863 were recorded in that earlier
UP sequence and are not treated as clean exits. The fallback 144 release was
actually launched but has not passed the full acceptance matrix. Later tests
ran during substantial host storage contention; the logs preserve timings and
failures rather than assigning every timeout to a proven browser defect.

`browser-final-01-up` runs the corrected MSI fixtures successfully and reports
55 main AI plus 7 provider cases passing. The general probe still explicitly
marks login-transition proof, legacy games, security mitigations and shutdown
as `not_tested`; other session/shutdown evidence is separate. The matrix now
requires page receipts and records unverified probe cases instead of treating
absence of a failure as full coverage. The test-media delays use the native
five-second Sleep fixture rather than ICMP timing. Host checks: 53 tests,
10 explicitly skipped; current helper cross-build resolves every direct import
and forwarded symbol against the extracted guest DLLs. Original NT build 05 supersedes build 04 and includes the additional diagnostics;
host cross-built executables remain a separate verification path.


## Standalone private experimental artifact

`W/image-01/XP25-Browser-Experimental.qcow2` is 3,591,700,480 bytes (32 GiB
virtual), SHA-256:

```
620a4d53fb2351365c2261a6978d0c1fc2727ff2fb33f9c89ced350eb9bf34a6
```

It is a compressed standalone QCOW2 with no backing file. `qemu-img check`
reports no errors; `qemu-img compare` reports identical guest disk contents
against the normally shut-down installation overlay. `W/image-01/manifest.json`
pins the release, source installation, prepared manifest and every installed
browser/helper/rollback/fixture file. The install-only image has no DevTools
bridge, test profile, dummy provider key or test proxy configuration. Existing
AI binaries and the original Winlogon/native UP stack come from the untouched
accepted AI base. Private engineering use only: acceptance and redistribution
are explicitly false in the manifest. A disposable overlay independently boots
this artifact for normal-shell restart testing.

The later MP Application log records four browser errors (event 1000) in
`chrome.dll` 150.0.7871.255 at offset `0x00842214`. The exact pinned binary's
fault site is `int3; ud2`. Official matching symbols identify a CHECK failure
in `base::win::TakeHandleOfType` (`base/win/scoped_handle.cc:77`), which rejects
an unexpected kernel-object type. The nearby stack-cookie handler in the
disassembly is not evidence that a cookie check triggered this crash. This
locates a protection-triggering failure, not its root cause. No cookie check,
trap, sandbox or certificate verification is disabled. Metadata/disassembly
remain private under `W/acquisition/crash-842214-*` and the MP serial log.


The standalone artifact independently boots the native NT 5.1 desktop and
passes the 13 shell checks in `browser-standalone-restart-01`. A normal shell
launch seeds fixture local storage successfully. After a graceful close the
between-launch inventory contains no chrome process; reopening then displays
a Supermium crash dialog and produces no verification-page receipt. The final
shutdown event is captured and the disposable proof overlay is frozen.
**Profile restart persistence fails acceptance outside DevTools as well.**
The standalone base stays unchanged. A pre-existing engineering-image
user-scope DPAPI error 1783 is documented by Milestone 6; its connection to
these browser crashes is not established and encryption is not disabled.

A follow-up native launcher change is being verified to validate a single
URL/document before constructing fixed browser arguments. This prevents
arbitrary browser switches being introduced through association arguments
while avoiding the quote-parsing bug. It is not yet in the image-01 artifact.


The official x86 symbol archive is independently pinned to SHA-256
`ec367c9a87f76c0340f8e738958aa4cefdc0aecc9a019c782ded7cdc10c8933d`.
The PDB GUID/age match the binary's CodeView record
`AA391345-1A73-D532-4C4C-44205044422E`, age 1. LLVM symbolization and a bounded
Application Error reader locate the handle-type CHECK without changing it.
The reference XP object-query source returns a typed Unicode name normally;
a handle-inheritance race or API-contract mismatch remains a hypothesis,
not an established root cause. Upstream's NT5.1 process-launch fallback
changes specific handle inheritance to inheriting handles generally; that
requires further isolation rather than weakening the type check.

Native build 05 compiles all six current utilities, and
`build/collect_browser_native.py` verifies 19 staged files against the build
media and resolves imports/forwarders against this guest's system DLLs. The
new URL/document launcher uses CreateProcess with an explicit executable and
fixed arguments, rejects extra arguments/quotes/control characters and
non-web URL schemes, and leaves ordinary shell operations to Windows.
It is under runtime validation in the new fallback matrix.

The 144 fallback's `persistence-independent-01/result.json` passes both local
storage and appearance-setting persistence on its MP guest. Eight of nine main
browser checks pass; only the fixed-delay download event observation failed.
The result is retained, not rewritten. The new harness waits for a completion
event up to 45 seconds, and a fresh native-launcher matrix covers UP/MP/TCG.


The updated native launcher has runtime evidence in
`browser-144-secure-01-mp`: all 13 association/shortcut checks and four rendered
HTTP/HTML/HTM/URL receipts pass. The install-only guest `browser-image-02`
checks script URLs, extra arguments and non-HTML documents all return 87,
with no chrome process in either inventory. The current helper is native
build 05 (`bb9048c10af008db8e4cdd8e388148deaa750dea2c43ce306f6f8f1b4f377650`).
The newer 144 MP browser test also fails after initial page rendering; earlier
persistence success does not establish repeatable stability. No fallback release
is yet accepted across all three modes.


## Reproducible private installation and packaging

Use a **new** output/run name for each command; the tools reject reuse. Build
media for the original NT toolchain with `build/prepare_browser_native.py`,
boot it using `vm/browser_lab.py --suite <native-media>/suite.cmd`, shut the
build guest down, then run `build/collect_browser_native.py`. The collectors
verify staged source hashes and guest import contracts, not merely PE presence.

The following example uses already verified native build 05 and the exact
fallback package. It produces another **unaccepted experiment**, not an
accepted browser/OS release:

```sh
browser_work=.work/browser-20261025
python3 build/prepare_browser.py \
  --package "$browser_work/acquisition/supermium_144_32_nonsetup.zip" \
  --pin components/browser/release-144.json \
  --browserctl "$browser_work/native-05/browserctl.exe" \
  --software-rendering --output "$browser_work/prepared-new"
python3 vm/browser_lab.py \
  --base ../xp25-ai/.work/ai-20261025/image-05/XP25-AI-Engineering.qcow2 \
  --sha256 ec22f45b67af19f584eb6ca0a286e943731298543aa1b910eab6ff42674bee2a \
  --media "$browser_work/prepared-new/browser.iso" \
  --suite "$browser_work/prepared-new/install-suite.cmd" \
  --name browser-install-new --mode up
python3 vm/browser_wait_shutdown.py \
  --run "$browser_work/runs/browser-install-new" --marker XP25_IMAGE_INSTALL_DONE
python3 vm/package_browser_image.py \
  --run "$browser_work/runs/browser-install-new" \
  --prepared "$browser_work/prepared-new" --output "$browser_work/image-new"
```

The default release pin remains latest 150; selecting 144 requires the explicit
pin above. Neither is promoted to accepted status by the packaging script.
Original archives, imported tools, symbols, full inventories, source excerpts,
guest binaries and QCOW2 files remain under ignored `.work/`. No upload, push
or registered-domain modification is part of these scripts. The reference
`Source/` Git diff is empty (`W/source-diff.txt`).


## Current native-launcher artifact and final matrix record

`W/image-02/XP25-Browser-Experimental.qcow2` contains official x86
144.0.7559.256 R5 and native helper build 05. It is 3,580,493,824 bytes,
32 GiB virtual, standalone with no backing file, SHA-256:

```
4d822af25ce27f5f467d123aeb23b01e2c4f1aac38c84ee3f063f64aa2df7e4a
```

Installed-file verification, image check and byte-for-byte guest-disk comparison
pass. The source install guest passes all 13 shell checks and rejects script
URLs, extra arguments and non-HTML targets (all return 87), with no browser
process launched by those negative tests. Explorer, original Winlogon and all
five AI binaries match the accepted AI input exactly; only the already verified
native MP kernel/HAL pair differs from its UP counterpart, as explicitly
recorded in `W/mp-kernel-base-01/manifest.json`. Nine system/app binary hashes
are checked in `W/image-02-system-check-01/comparison.json`.

The complete `matrix-144-secure-01/result.json` reports **failure in all three
modes** (UP, MP and TCG) on a later page load. Both 150 and 144 remain unaccepted.
The failed diagnostic overlays are checked/frozen after an explicit forced
stop, labelled accordingly; they are not normal-shutdown proofs. A separate
older 144 MP run records 55+7 AI cases, normal shutdown, successful profile/
font persistence and the completed downloaded fixture hash
`1d94b07c8028c3b4e886301ea0373116da9c4b0ed4f9ac58950308ce65eb9cc2`.
This supplementary offline evidence preserves its original missing-event
failure and does not override the later stability failures.

The host CONNECT gateway independently rejects loopback, an unapproved host,
port 22 and a non-CONNECT request with HTTP 403 (`gateway-denials-01.json`).
No browser/certificate protection is bypassed. Screenshots and their hashes are
under `W/deliverables/`; full dependency graphs stay in `W/ie-audit-03/`.
The new standalone artifact has a separate disposable first-boot/restart proof;
its results below do not change the explicit unaccepted status.


The image-02 proof overlay independently boots NT 5.1/Explorer, passes all 13
shell checks, and renders the first persistence fixture. Chrome is absent
between launches and after the final graceful close. The second fixture is
requested and its complete HTTP 200 response reaches the guest (packet capture),
but its JavaScript receipt never arrives. No new chrome Application Error is
found in the extracted proof Event Log; this failure is not labelled a proven
144 crash. Restart stability remains unaccepted. A guest-requested shutdown
event is captured and the proof overlay is frozen normally.

The 144 proof samples six Chrome processes at a combined sequential working set
of 181,399,552 bytes (about 173 MiB), not a synchronized peak. Sampled tokens
report `restricted=0`; one sampled process belongs to a job. Unlike 150, the
sampled 144 renderer command has no explicit `--no-sandbox`. Neither token
observations nor absence of that switch prove containment; version-specific
sandbox behavior remains limited/unverified. The image-02 manifest clarifies
that distinction and retains its initial metadata copy. The four inspected
Run/RunOnce keys contain only ctfmon and the existing RoverAI indexer, with
no IE browser startup entry. Other Active Setup and third-party startup paths
remain outside that focused observation. No AI startup entry is removed.

Current status remains **Milestone 7 incomplete**: installed native browser
integration, rollback, provenance pins, dependency graphs, screenshots and
standalone private artifacts exist, but repeatable browser operation and the
full acceptance matrix do not pass. Resolving the protected handle-type failure
and later renderer/page-load failures requires further native runtime debugging;
removing the guard or disabling browser security is not an acceptable fix.
