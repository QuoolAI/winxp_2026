# Browser stability and security follow-up, 2026-10-26

Milestone 7 remains **unaccepted**. Neither tested Supermium version is suitable
for unrestricted Internet access on XP25. No new accepted engineering image is
produced. The existing browser adapter, associations, rollback data and previous
experimental images are preserved.

Evidence root: `.work/browser-stability-20261026/` (abbreviated `S` below).
The preceding experiments remain under `.work/browser-20261025/` (`B`).
`S/existing-results-review.json` indexes the earlier experimental JSON results,
including parse failures; those failures have not been silently discarded.
Each new VM has its own overlay, name, MAC, private QMP socket and isolated
network namespace without an uplink. Registered user VMs are not test subjects.

## First captured application failure

`S/runs/bdiag150-sp3-up-01` reproduces an actual Supermium 150 failure on the
original XP SP3 control: cycle 1, root PID 1008, thread 1360, first and second
chance `0x80000003`, address `0x217b96f8`, **chrome.dll RVA `0x77b96f8`**.
The root exits `0x80000003`. Cycles 2 and 3 exit zero and render the fixture.
The matching official 150 PDB identifies the failing inline CHECK in
`base::(anonymous)::CompletionIOPortThread::ThreadMain`,
`base/files/file_path_watcher_win.cc:357`. The caller at RVA `0xa4476f` is
`base::ThreadFunc`. EAX contains **995 (`ERROR_OPERATION_ABORTED`)**, while the
check expects 5 (`ERROR_ACCESS_DENIED`). These are not missing-import or
out-of-memory failures.

Official PDB archive SHA-256:
`ec367c9a87f76c0340f8e738958aa4cefdc0aecc9a019c782ded7cdc10c8933d`.
PDB GUID `AA391345-1A73-D532-4C4C-44205044422E`, age 1, matches the dump's
CodeView identity. Dumps, module lists, register values and labelled frame
chains are in `S/control150-capture-01`; the symbol tools and their commands
remain private under `B/debug-tools-01` and `B/symbols-150`.

`bdiag150-xp25-cirrus-01` subsequently captures the **same RVA and error 995**
on XP25, cycle 1, PID 1612/thread 1952, in the network-service utility. Only a
first-chance assertion is observed there; that child exits zero and the browser
root also exits zero. Do not describe it as a second-chance root crash.
All three JavaScript receipts arrive. Its pre-dump working set is 33,079,296
bytes, private commit 20,549,632 bytes, with approximately 1.7 GB physical RAM
available. Full-memory dump collection subsequently inflates working-set
measurements; those later samples are not normal browser memory measurements.
`SYSTEM_MEMORY.available_virtual_low` is the observer's address space, not a
measurement of free Chrome virtual address space.
See `S/xp25150-cirrus-capture-01/first-exception.json` and `events.log`.

The native `browser_iocancel` probe distinguishes two real NT behaviours:
eight ordinary directory notifications complete; eight handle-close
notifications complete with zero bytes/success; eight notifications issued
by a worker that then exits complete with **FALSE/995**, zero bytes, the
correct completion key and the original OVERLAPPED address. The directory
handle is still open in the last case. XP25 KVM and original SP3 both reproduce
this contract. No return value is translated or faked. This makes issuing-thread
lifetime a concrete upstream investigation target; it does **not** prove that
the browser's issuing thread exited in the captured incident.

The reviewed official 144 watcher source checks for error 5 before inspecting
the watcher state. A safe browser correction must preserve cancellation and
watch-lifetime semantics, including watches that remain valid. Ignoring error
995, removing the CHECK, or changing XP's API return value is not a verified
fix. No XP25 kernel/API correction is justified by this evidence, and no
browser binary is patched. The earlier scoped-handle type CHECK at RVA
`0x842214` remains a separate unresolved incident.

## Controlled comparisons and unsuccessful captures

The original control parent is
`../winxp_2026/.work/xp-sp3-install-20261018/xp-sp3.qcow2`, SHA-256
`e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c`.
XP25's UP parent is AI image-05, SHA-256
`ec22f45b67af19f584eb6ca0a286e943731298543aa1b910eab6ff42674bee2a`.
Both are frozen parents; only new children are written. The single-vCPU
comparisons use i440fx 8.2, qemu32, RTL8139, standard VGA and 2048 MiB RAM,
with identical diagnostic media. Unique MAC addresses are intentional.

| Run under `S/runs/` | Observation |
| --- | --- |
| `bdiag150-sp3-up-01` | Three JS receipts; first root shutdown crashes as above. |
| `bdiag150-xp25-up-02`, `bdiag150-sp3-up-02` | Corrected debugger: each has three JS receipts and three zero root exits; no application exceptions captured. |
| `bdiag150-xp25-cirrus-01` | Cirrus VGA/2 GB: three receipts, three zero root exits, same watcher assertion in network service. Graphics change does not eliminate that assertion. |
| `bdiag150-xp25-tcg-01` | TCG/standard VGA/2 GB: first close reaches 90-second deadline; no JS receipt or application exception captured. Guest later shuts down normally. |
| `bplain144-xp25-mp-01` | Actual MP kernel/HAL, KVM two vCPUs/2 GB, no Windows debugger: root exits `ffff7002`, `80000003`, `ffff7002`; two of three JS receipts. No stack is inferred from an exit code. |
| `bdiag144-xp25-mp-01` | Same MP hardware under debugger: first close reaches deadline, no captured application exception. This observer effect is not a successful stability result. |
| `btrace144-sp3-up-01`, `btrace144-xp25-up-01` | Fresh 144 profiles render modern JavaScript; executing-renderer token tests fail isolation on both. |

The initial `bdiag150-xp25-up-01` result is **invalid as a browser crash**:
the first debugger assumed NTDLL's stock load address and passed XP25's initial
loader breakpoint through unhandled. The corrected debugger recognizes the
mapped NTDLL module rather than a fixed address and consumes only its initial
loader breakpoint. All application exceptions still reach real handlers.
The raw failed capture and its interpretation remain in `S/xp25150-capture-01`.

The unmonitored KVM kernel-GDB prototype in `bdiag150-xp25-plain-01` fails
with `Invalid hex digit 79` after matching the live kernel checksum. It does
not provide a browser exception. That private VM is forcibly stopped/frozen,
explicitly distinguished from normal shutdown. The unverified prototype is
retained only in `S/capture_browser_exception-prototype.py`, outside shipping
tooling. Successful debugger runs do not validate this failed GDB method.

Standard VGA also produces D3D shared-context errors on stock SP3. The browser
can render despite them. Cirrus and 2 GB RAM improve individual observations
but do not establish a graphics fix, font fix, memory exhaustion diagnosis or
stable restart. The original 1 GB failures are not erased by short 2 GB passes.
No new missing NT 5.1 API has been established by these captures.

## Sandbox: failed token boundaries, not a positive security result

`browser_sandbox` creates a new protected directory and registry key with only
Administrators/System access. Its own unrestricted token can write both;
a known restricted token is denied both with error 5. The probe duplicates
the observed browser tokens and impersonates them **in the probe process**,
without injecting browser code, enabling privileges or modifying existing ACLs.
It records process roles, primary/impersonation tokens, enabled privileges,
restricted SIDs and process-open failures. It then removes its own test objects.

The isolated DevTools trace issues a unique `console.timeStamp` from the test
page and identifies the actual JavaScript-executing renderer/thread:

| Guest | Trace result | Corresponding native observation |
| --- | --- | --- |
| Original SP3 | PID 2052/TID 2056, `renderer-trace-03/result.json` | Primary token unrestricted; main-thread token restricted SID count 9, enabled Admin SID; both duplicated tokens write the protected file and registry objects. Second probe follows the trace. |
| XP25 | PID 204/TID 144, `renderer-trace-01/result.json` | Same failed boundaries for primary and main-thread tokens; controls still deny the known restricted token. |

These tests establish that the observed tokens lack the required filesystem and
registry restrictions. They are not an injected renderer exploit test, a complete
job/UI restriction audit, or proof that every sandbox layer is absent.
Nevertheless, renderer isolation fails the milestone's acceptance requirement.
The official [144 renderer source](https://github.com/win32ss/supermium/blob/v144-r5/content/renderer/renderer_main.cc)
sets `need_sandbox = false` before Windows 10, explaining why the initial thread
token is not evidence of completed lockdown. The official
[150 sandbox patch](https://github.com/win32ss/supermium/blob/v150-r2.01/supermium_150_core_sandbox.patch)
also contains older-Windows no-sandbox policy paths. Version 150's actual
NT 5.1 child commands contain internally appended `--no-sandbox`.
No such flag is supplied by the XP25 adapter or these launch fixtures.

The SP3 firewall initially blocks the diagnostic bridge. Its original state
is recorded; one temporary TCP 9223 exception is scoped exclusively to
`10.25.0.1`, inside the no-uplink namespace, and deleted before shutdown.
Firewall service/protection is not disabled. The bridge and DevTools endpoint
are test-only and are never installed by the production integration scripts.
Only fresh fixture profiles are inspected; collectors exclude Profile/history,
cookies, passwords and session tokens.

## Native desktop Help replacement

`components/help/native_help.c` implements a Win32 Help viewer using a search
edit, topic list, read-only text edit, keyboard-accessible native settings
buttons and nine original local topics. It uses the existing Luna controls.
It contains no HTML renderer, WebBrowser COM adapter or scripting engine.
It is a limited desktop Help replacement, not a complete replacement for the
original Help and Support content or third-party CHM/HLP interfaces.

`prepare_native_help.py` accepts the exact previously verified source-built
Explorer SHA-256
`487830836b1543a2e8fd2600b0bb08fb9145d8bf303afbf9817d0151e4f8af1e`.
In a disposable copy it changes only string ID 732 from
`helpctr.exe>-FromStartHelp` to `XP25Help.exe`. Resource verification checks code
sections, imports, exports, version information, other resource payloads and
the other 15 strings in that block. The new application gets its own HKLM/HKCU
App Paths records; original helpctr records, executables, CHM/HLP handlers and
all shared IE DLLs remain untouched.

Native build 08 produces ten executables using the original NT compiler;
31 staged input files and all direct/forwarded imports are verified by the
collector. Native Help executable SHA-256:
`f645e78a846d8bd09ffc40cfdee986437c17fd75331c35c1dfd953cf99bb692d`.
The build-08 I/O probe differs from the final source only by the subsequent
warning-clean line break; both native and cross builds are recorded separately.
The final host cross-build is `S/tools-14`, not substituted for the NT build.

`native-help-up-01` proves an actual Start-menu Help launch on XP25 KVM with
the resource change. The later native Help passes **14 GUI-control tests** on
stock SP3 KVM and XP25 TCG: topic search, negative search, all nine topics and
absence of loaded MSHTML/JScript/VBScript after navigation. The self-test report
is written explicitly even when a GUI process has no inherited console handle.
See `help-contract-sp3-up-01` and `help-contract-xp25-tcg-01` serial logs.
Screenshots include `native-help-up-01/help-start-ready.png` and
`help-contract-xp25-tcg-01/help-tcg-ready.png`.

Rollback is rehearsed in **another new overlay**. `install_native_help_overlay.py
--restore` verifies the saved original Explorer and restores its exact bytes
offline. `native-help-rollback-up-01` restores both application-registration
scopes (originally absent), then launches the original Help and Support from
the Start menu. Its screenshot and runtime inventory show the original Help
working, including its retained Trident dependencies. This is recovery evidence,
not removal of those libraries.

## Reproduction and remaining work

Use `build/prepare_browser_native.py` and `build/collect_browser_native.py` for
the original compiler. `build/browser_diagnostic_media.py` verifies the prepared
browser manifest before adding native diagnostics. `vm/browser_lab.py` now
accepts a fresh run root, original-control root suite, 256–3072 MiB RAM and
standard/Cirrus/VMware VGA choices. Tested VGA choices here are standard and
Cirrus; VMware remains untested. `build/collect_browser_diagnostics.py` reads
only frozen private guests and excludes browser profiles.
`build/read_browser_dump.py` reports x86 exception and normal-snapshot thread
contexts, matching module identities, frame-pointer chains and **separately
labelled unverified stack candidates**. Stack words are not promoted to frames.

The focused host tests pass 8/8. The full host suite runs 56 tests, with 10
explicit private-input skips and no failures (`S/all-host-tests-01.log`).
These host tests do not certify a guest boot, sandbox or browser acceptance.

Remaining requirements include a browser implementation with demonstrated XP
renderer lockdown; correction and validation of watcher cancellation/lifetime;
unmonitored 144 crash and restart stacks; repeated KVM/TCG browser regressions;
and the complete application, installer, AI, HTTPS and shutdown acceptance
matrix on the final combined image. Earlier preliminary TLS/certificate and
download results remain valid only for their recorded runs. They are not a
new full regression pass. No certificate bypass, fake-success API, security
guard removal, OS security downgrade or shared-IE-DLL deletion is implemented.
No new accepted or publicly redistributed browser image is generated.

## Watcher compatibility fix, reduced-privilege containment and default Internet policy (2026-10-27)

Evidence root: `.work/browser-fix-20261026/` (abbreviated `X`). All inputs are the
same frozen parents; only new children are written. The private HTTPS CONNECT
gateway (`X/https-gateway.sock`, same allowlist as before) and the per-run
isolated namespaces are unchanged. `X/fix-summary.json` consolidates the results
below. No Microsoft component, `Source/` file or browser binary is modified; the
original Supermium wrapper is preserved byte-for-byte.

### Root cause and the XP25 pwrp_k32 proxy

The first captured application failure (`chrome.dll` RVA `0x77b96f8`, the
`ERROR_OPERATION_ABORTED` CHECK in `CompletionIOPortThread::ThreadMain`,
`file_path_watcher_win.cc:357`) is a real NT 5.1 contract difference, not a
missing import. NT 5.1 cancels a pending IRP when the thread that **issued** it
exits (`IoCancelThreadIo`); Vista and later keep I/O on completion-port handles
alive. Chromium arms a directory watch with `ReadDirectoryChangesW` on a
thread-pool worker that can later be reclaimed, then CHECKs that the port never
reports cancellation. On XP the reclaimed worker's exit cancels the watch and the
port returns error 995, so the CHECK aborts. Supermium reaches
`ReadDirectoryChangesW` through its own `pwrp_k32.dll` (byte-identical in 144 R5
and 150 R2.01, SHA-256 `bbd3fc48…`), so the fix lives there, not in the OS.

`components/browser/xp25_pwrp.c` builds a replacement `pwrp_k32.dll`. The pinned
original is kept beside it as `pwrp_k32_sm.dll`; `build/pwrp_proxy.py` regenerates
`components/browser/pwrp_k32.def` from the pinned original so every one of its
1703 named exports keeps its name, ordinal and original forwarder, except
`ReadDirectoryChangesW`. For an asynchronous watch with no event and no
completion routine (exactly Chromium's IOCP shape), the proxy re-issues the real
call from a single persistent thread via `QueueUserAPC`, so no transient worker
owns the IRP; the real result and last error are returned unchanged. Every other
call shape — a request with an event, a completion routine, a synchronous handle,
or a call from the proxy's own thread — falls through to the original export with
unaltered NT 5.1 semantics. Nothing is translated: cancellation by handle close
still surfaces as 995 to the caller. A host export-table equality check and a
native-build export check both require the proxy's table to match the generated
definition exactly (`tests/test_browser_compat.py`, `build/collect_browser_native.py`).

### Watcher fix verified (native `browser_watch` probe and A/B incident test)

`tests/guest/browser_watch.c` loads both DLLs and reproduces Chromium's pattern:
arm a watch on a worker thread, let the worker exit, then change or close the
directory. On **both** XP25 KVM and the original SP3 control the probe reports
`WATCH_SUMMARY failures=0` across ~35 assertions: with `kernel32` and the original
wrapper, an exited-issuer watch completes with `ERROR_OPERATION_ABORTED`; with the
proxy the same watch completes normally (24-byte `FILE_ACTION_ADDED` on change,
zero bytes on handle close), 32 of 32 concurrent exited-issuer watches complete,
event-based requests still return the NT 995 unchanged, a completion-routine
request runs on its issuing thread, and the invalid-handle error and
pending-success last-error match `kernel32` exactly. See
`X/collect-fab150-{xp25-up,sp3-up}-01` logs.

An A/B diagnostic (`build/browser_diagnostic_media.py --mode watch-ab`) alternates
the original wrapper and the proxy in equal debugger and unmonitored blocks on one
image, verifying the on-disk DLL layout (`fc /b`) before each block. On XP25 the
watcher CHECK (`0x77b96f8`) fired in an original-wrapper block (first and second
chance of one incident) and in **no** proxy block; across both guests the count is
`watcher_check_in_original_blocks` vs `watcher_check_in_proxy_blocks` = 2 vs 0 on
XP25 and 0 vs 0 on the control (the assertion is timing-dependent and did not
recur in the control's original block this run, but is captured in
`B/.../bdiag150-sp3-up-01`). Evidence: `X/fab150-*-ab-report.json`,
`X/collect-fab150-*`.

**Honest limits.** The watcher CHECK is eliminated, but the proxy does **not** make
Supermium fully stable on XP25: proxy blocks still show occasional hangs (one
debugger-deadline in an XP25 proxy block) and the XP25 A/B guest later wedged and
was force-stopped and frozen with a `failure.json` (`X/runs/fab150-xp25-up-01`).
A separate, unfixed CHECK remains — `base::win::TakeHandleOfType` at
`0x842214` (`scoped_handle.cc:77`), reached from
`base::shared_memory::Deserialize` when a child resolves the shared-memory
`Section` handle passed through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
(`launch_win.cc`). That attribute is emulated by progwrp on NT 5.1 and is a
distinct handle-inheritance investigation, not addressed here. No CHECK is removed
and no API return value is faked.

### Reduced-privilege containment (no renderer sandbox exists)

Supermium sets `need_sandbox = false` before Windows 10, so there is no renderer
sandbox on NT 5.1 (the 150 package's own network/utility child commands already
carry `--no-sandbox`; XP25 never adds that switch). Instead of leaving the browser
fully privileged, every XP25 entry point now launches `chrome.exe` with a SAFER
**Normal User** token (`browserctl.c`: Administrators deny-only, privileges
dropped except change-notify) through `CreateProcessAsUser`, and the Start-menu
client, shortcuts and all shell associations go through the windowed
`XP25Browser.exe` so children inherit that token. Launch fails closed if the token
cannot be built; no `CreateProcessW` fallback exists.

The `browser_sandbox` probe, run against the live browser under both the launcher
and a shell association on an MP guest, shows the browser root and every child
(primary tokens) **denied** write to an administrator-only file and registry key
with error 5, while a baseline unrestricted token writes both and a known
restricted token is denied both — so the test discriminates. Renderers were
observed and the fixture page rendered. This is process-level privilege reduction,
not a per-renderer sandbox: the same probe records that the reduced token can
still write the user's own profile and open the shell for injection, because NT
5.1 has no integrity levels or UIPI. Evidence: `X/runs/fcontain150-mp-01/serial.log`,
`X/fix-summary.json` (`containment`).

Because no renderer sandbox is available, the experimental image keeps
unrestricted Internet browsing **disabled** by default: the installer writes a
Supermium `URLBlocklist` of `*` with an `URLAllowlist` of local files, internal
pages and the private lab host only (`HKLM\SOFTWARE\Policies\Supermium`,
reversible through the existing rollback scopes). An administrator adds approved
hosts explicitly. The HTTPS certificate cases in the regression use a test-only
allowlist added at run time, never shipped.

### Guest matrix: shell/rendering verified; DevTools deep-regression blocked

A fresh install-only guest built from the 150 package with the proxy, launcher and
policy shut down normally; its negative tests reject `javascript:`, extra
arguments and non-HTML documents (all 87) with no browser launched
(`X/runs/finstall150-01`). The KVM-UP, KVM-MP and TCG matrix on that base
(`X/matrix-150-01`) each pass the 13 shell/association/NT-version checks (including
the new `watch_proxy_layout` and `internet_blocklist_policy` cases) and render
HTTP, HTML, HTM, URL and HTTPS through the reduced-token launcher (five JavaScript
receipts per mode, `javascript:` rejected 87). The DevTools-driven deep regression
(repeated navigation, multi-tab, the four certificate cases, download, profile and
appearance persistence) **did not complete in any mode**: the CDP WebSocket timed
out after the HTTP `/json/version` endpoint returned the real browser version,
which matches the host storage-contention timeouts recorded in the earlier
checkpoint (the disk was ~98% full during these runs) and is not a browser-core
regression — the reduced token does not block DevTools, since its HTTP endpoint
answered. The three matrix guests were frozen with `failure.json`. Deep-regression
acceptance under contention-free storage remains outstanding; no failure is
recorded as a pass.

### Status

Milestone 7 remains **unaccepted** and no new accepted image is produced. Verified
this checkpoint: the directory-watcher cancellation CHECK is fixed by a
provenance-pinned, export-equal compatibility proxy and confirmed by a native
probe on XP25 and the SP3 control; XP25 entry points launch the browser with a
SAFER Normal User token whose file/registry boundaries are enforced in a live
guest; the default image blocks Internet browsing; shell integration and
reduced-token rendering of every association type pass under KVM-UP, KVM-MP and
TCG. Outstanding: the `0x842214` shared-memory handle-type CHECK, residual
hangs/restart stability, and the DevTools deep-regression matrix on contention-free
storage. Host tests: 64 run, 10 private-input skips, no failures
(`X/all-host-tests-01.log`).

## Handle-type CHECK (0x842214) investigation, 2026-10-27

Evidence root `.work/browser-fix-20261026/` (`X`). This continues the watcher-fix
checkpoint above and does **not** change acceptance: Milestone 7 stays unaccepted.

### Exact assertion, stack, process and handle

The `0x842214` crash is `base::win::TakeHandleOfType(handle, "Section")` failing
its `CHECK_EQ(*type_name, object_type_name)` (`base/win/scoped_handle.cc:77`). The
reliable in-process minidump (`X/collect-fab150-sp3-up-01/dprox1-c4-p2064-*.dmp`,
captured during the watcher A/B run, so the XP25 pwrp_k32 proxy was installed and
is not implicated) gives the full frame chain:

```
TakeHandleOfType                               base\win\scoped_handle.cc:77
base::shared_memory::Deserialize               base\memory\shared_memory_switch.cc:244
base::shared_memory::ReadOnlySharedMemoryRegionFrom  shared_memory_switch.cc:396
base::FieldTrialList::CreateTrialsInChildProcess     base\metrics\field_trial.cc:656
content::InitializeFieldTrialAndFeatureList          content\child\field_trial.cc:37
content::ContentMainRunnerImpl::Run / RunContentProcess / ContentMain / ChromeMain
```

The faulting process is consistently the **gpu-process** child. It is parsing its
`--field-trial-handle=<value>,i,...` switch: `i` means the field-trial read-only
shared-memory **Section** is passed by handle **inheritance**, and `Deserialize`
calls `TakeHandleOfType(Uint32ToHandle(value), "Section")` directly, trusting the
inherited value. In the dump the registers are `eax=7 ecx=4` — `len("Section")`
vs an actual type-name length of 4 — and the stack holds the wide string `"File"`
and the handle value `0x72c` (1836), the child's own `--field-trial-handle=1836`.
So handle value 1836 in the gpu child is a **File**, not the field-trial Section.
A second XP25 capture (`X/runs/fftdebug-xp25-01`, gpu pid 2020, value 828) agrees:
the field-trial handle value is not a valid Section at the CHECK.

### Origin: not the compat proxy, not XP25, not basic progwrp inheritance

`tests/guest/browser_inherit.c` reproduces Chromium's launch pattern
(`base/process/launch_win.cc`) against the installed progwrp: a read-only Section
is marked inheritable and listed in a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, then
`CreateProcessW` runs with `bInheritHandles=TRUE` and `EXTENDED_STARTUPINFO_PRESENT`;
the child reports the NT type each inherited handle **value** names (via
`NtQueryObject`, as `GetObjectTypeName` does). On **both** XP25 KVM and the stock
SP3 control the listed Section's value is preserved and reads as `Section` 6/6, and
the child exits 0 (`X/runs/finherit-{xp25,sp3}-up-02`, `X/crash-842214-summary.json`).
So progwrp's handle-list inheritance preserves a Section's value and type in
isolation. The one deviation observed is that the **unlisted** event also inherits
(6/6): progwrp does **not** restrict inheritance to the listed set, unlike real
Windows. That over-inheritance is a latent correctness/security gap but does not by
itself displace the field-trial value (inherited handles keep their own values), and
the isolated listed-Section case works, so it is not demonstrated to be the cause.

The crash reproduces on **stock, unmodified SP3** (`X/collect-fab150-sp3-up-01`),
so it is not an XP25 modification. It is intermittent (absent from 3 of the most
recent debug runs). The conclusion is that `0x842214` is a Supermium/Chromium
gpu-process handle-lifetime defect on NT 5.1 — the field-trial Section's inherited
handle is not valid as a Section by the time the gpu child reads it — and the
protective CHECK correctly catches it.

### No safe compat-layer fix; not patched

Unlike the watcher CHECK (fixed cleanly inside progwrp's own `ReadDirectoryChangesW`),
`0x842214` has no correct fix at the pwrp_k32 compatibility layer: the defect is in
the browser's own child-launch/handle handling, and the only ways to suppress the
crash would be to modify `chrome.dll` (not our code) or disable/weaken the CHECK —
both forbidden, and the CHECK is a genuine type-confusion guard worth keeping. The
debugger-side handle probe (`tests/guest/browser_debug.c`, `FIELDTRIAL_PROBE`) could
not duplicate child handles reliably (`ERROR_INVALID_HANDLE` from the debug process
handle), so it did not settle whether the Section was never inherited or inherited
then closed and its value reused; the in-process minidump remains the authoritative
evidence. No CHECK is removed, no handle result is faked, and the over-inheritance
gap is documented rather than "fixed" speculatively. This remains an open,
characterized defect.

## Stability, restart and DevTools regression on KVM, 2026-10-27

With the watcher proxy and reduced-token launcher installed and the host disk no
longer saturated (~21 GB free, versus the ~98%-full contention of the earlier
checkpoint), the full browser regression matrix was re-run on the frozen install
base (`X/runs/finstall150-01`, SHA-256 `06fbba27…6b6da07`) via
`vm/browser_matrix.py`. Evidence: `X/matrix-150-02`, `X/matrix-150-02-summary.json`.

**KVM single-vCPU (up) and two-vCPU (mp) both pass the entire functional
regression.** The DevTools-driven browser checks all pass in each mode — modern
JavaScript, local HTML over HTTP and `file://`, multiple tabs, TLS 1.2/1.3 to a
valid host, and rejection of expired (`ERR_CERT_DATE_INVALID`), wrong-hostname and
untrusted certificates; the download completes; and the default Internet policy
blocks both an unapproved lab subdomain and a public site
(`policy_blocks_lab_subdomain`, `policy_blocks_public_site` — `URLBlocklist=*`).
**Profile and appearance-setting persistence across a browser restart now pass**
(`profile_persists`, `appearance_setting_persists`) — the failure recorded at the
earlier checkpoint. Shell/association checks, the reduced-token launcher rendering
of HTTP/HTML/HTM/URL/HTTPS, the 55+7 AI probe cases, and a normal guest-requested
shutdown all pass. The only non-passing check is `full_regression_coverage`, the
harness's explicit marker that four probe cases remain `not_tested`
(`login_transition`, `legacy_games`, `security_mitigations`, `shutdown`); it is a
coverage gap, not a browser failure.

This resolves the earlier DevTools WebSocket timeout as **host storage contention,
not a browser defect**: with disk headroom the CDP connection and the full
scripted session succeed on KVM. The watcher proxy's persistent I/O worker shows
no cleanup problem across these repeated launch/navigate/restart/shutdown cycles
(and the `browser_watch` probe independently completes 32/32 concurrent
exited-issuer watches); no watcher CHECK occurs in any of these runs.

**TCG remains timing-limited.** Under single-threaded TCG emulation the browser
still renders the shell and all five ShellExecute document types (four JavaScript
receipts in `X/runs/fmatrix150-02-tcg`), but the DevTools CDP calls exceeded the
45-second per-call timeout and the automated deep regression did not complete;
this is harness/emulation slowness, not a browser crash (the same image passes
fully on KVM). The CDP timeout is now configurable (`XP25_CDP_TIMEOUT`,
`vm/browser_cdp.py`), and `vm/browser_matrix.py` raises it to 240 s for TCG, but a
re-run at that budget (`X/matrix-150-03`) **still** timed out on the first CDP call
while again rendering the shell and all five ShellExecute document types — a
single-thread-emulation wall, not a browser defect. DevTools-driven deep
automation is therefore impractical under TCG; TCG browser functionality is
evidenced through the non-DevTools ShellExecute path instead. Both failed TCG
workers left their guests running (the harness detaches guests), so each was frozen
with a `failure.json`, not left orphaned.

Milestone 7 is **not** promoted: `full_regression_coverage` is still incomplete by
design (the four `not_tested` cases), the `0x842214` handle-type CHECK remains an
open intermittent defect, renderer sandboxing does not exist on NT 5.1 (the image
keeps Internet access disabled by default), and no new accepted or Internet-safe
image is produced.
