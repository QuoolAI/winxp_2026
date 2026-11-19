# Modernization roadmap (after Milestone 8.4)

Priorities follow the Milestone 8.4 rule: confirmed memory-safety and
synchronization defects first, then ownership and hardening, then measured
performance, then structure. Each item names the evidence that justifies it
and what would prove it done. Item IDs are referenced from the
[static analysis](static-analysis-findings.md),
[architecture audit](architecture-modernization-audit.md) and
[optimization](optimization-opportunities.md) documents.

## Summary

| Component | Problem | Severity | Proposed improvement | Risk | Status |
| --- | --- | --- | --- | --- | --- |
| Winlogon | No screen saver ever starts, so a password-protected screen saver never locks an idle session; USER repeats the notice twice a second while idle (SA-0) | Medium (security: no idle lock) | Start the user's screen saver as the original Winlogon does: `WlxScreenSaverNotify`, the screen-saver desktop for secure ones, lock on return | Medium (session and desktop flow) | **Done**: logging flood in 8.4; screen savers and idle lock in R-0 (`020eaf40…`, [record](winlogon-screen-saver.md)) |
| ClippyAI | Exit during an open question hung 15 s, then freed state under the worker (SA-1) | Medium | Answer questions "no" while shutting down; never wait for a worker that waits for the UI thread; never free under a running worker | Low | **Done** (8.4) |
| RoverAI Explorer bar | Search thread could outlive `RoverAIBand.dll` in Explorer (SA-2) | Medium | Thread holds its module; `FreeLibraryAndExitThread` | Low | **Done** (8.4) |
| RoverAI index | Logon rescan dominated by long-prefix binary searches (SA-10) | Performance | Cursor lookup in the directory's range, inline case folding | Low (differential test) | **Done** (8.4): host −76%, guest KVM −21% |
| XP25 AI binaries | No stack cookies (SA-9) | Hardening | `/GS` via `BUFFER_OVERFLOW_CHECKS` | Low | **Done** (8.4) for 5 targets |
| Winlogon, XP25Sec, XP25Audit | No stack cookies | Hardening | `/GS`; explicit `__security_init_cookie` for the `UMENTRYABS` tools | Medium (Winlogon is SYSTEM and session-critical) | R-2 |
| Source-built Microsoft components (25) | Checked builds, no `/GS`, no SafeSEH | High (Milestone 8 baseline) | Free builds; `/GS` where the tree supports it | High | R-2, R-3 |
| Source-built `lsasrv`, `services`, `ws2_32`, `win32k`, `user32`, `gdi32` | Missing every fix after 1106 | High | Assess post-1106 bulletins; fix what is located in source | Medium (core binaries) | **R-1 done**: 6 fixes in win32k/user32/gdi32; dozens suspected, not located ([record](source-built-component-assessment.md)); R-1b |
| RoverAI background indexer | Stop path frees state under a scanning thread; lock order inverted (latent, SA-3) | Low | Cancellable watcher scans, unbounded join or no free, lock order fix, or remove the dead stop path | Low | R-6 |
| XP25Broker | Cancelled connect not awaited; spin on event creation failure (SA-4, SA-5) | Low | Wait after `CancelIo`; fail closed | Low | R-7 |
| RoverAI → ClippyAI IPC | Argument quoting (SA-6); duplicated sender (SA-12) | Low | One sender; `CommandLineToArgvW`-compatible quoting | Low | R-5 |
| RoverAI search | Substring search hotspot (SA-11); second-scan slowdown | Performance | Fold table + first-character scan; investigate heap reuse | Low | R-4 |
| `xp25agent.dll` / RoverAI | Component cycle: the agent DLL compiles RoverAI's engine | Structure | `roverengine` static library linked into `xp25agent.dll`; same exports | Low | R-8 |
| Winlogon notifications | One failing package stops the others (SA-7) | Info | Decide: keep fail-closed or match the original Winlogon | Medium (session start) | R-9 |
| Large functions | `rover_query_parse` (complexity 137), `xp25_analyze_network_text` (82), XP25Sec `apply`/`rollback` (60/53) | Maintainability | Split behind existing tests; add differential tests first | Medium | R-10 |
| Lab harnesses | Repeated QEMU/QMP/overlay code across `vm/*_lab.py` | Maintainability | Shared lab core | Low | R-11 |
| Python tooling | 13 unused imports/locals | Hygiene | Remove | None | R-12 |
| Lab evidence | Unexplained guest resets leave no dump (`m84-std-tcg-01`) | Diagnostics | Small memory dumps in lab overlays; collect them | None | R-13 |

## Items

**R-0 — Screen savers and idle lock in the XP25 Winlogon. Done**
([record](winlogon-screen-saver.md)): the saver runs on `WinSta0\Screen-saver`,
a secure session saver ends in a lock, and the guest gates pass on KVM-UP,
KVM-MP and TCG. The original problem: USER asks Winlogon
to start the screen saver (`LOGON_INPUT_TIMEOUT`). The original Winlogon asks
MSGINA through `WlxScreenSaverNotify` whether to start it and whether it is
secure. It then runs the user's `SCRNSAVE.EXE` with the screen-saver start flag,
so USER registers it and stops repeating the notice; a secure one runs on its
own desktop and the session is locked when it ends. XP25 does none of this.
Since 8.4 the repeats are only counted, not logged one by one. Until R-0, a
password-protected screen saver setting gives no protection. Lock the station
with Win+L or Ctrl+Alt+Del. *Done when* the Winlogon lifecycle harness gains
idle-lock gates (secure and non-secure, at the logon desktop and in a session),
and the idle probe sees the notice stop once the screen saver runs.

**R-0b — Winlogon diagnostics channel.** Every Winlogon event opens COM1
exclusively, writes one line and closes it. Any other COM1 user (a serial
device, the lab's own fixtures) fails whenever its open coincides with a
Winlogon line. In Milestone 8.4 this cost a standard-user regression run its
first two markers at logon (`runs/m84-std-up-01`; the account was created
correctly). Keep one handle open for the process lifetime, or move
diagnostics off COM1 in production builds and keep the file log. That log has
no size limit today; add one.

**R-1 — Analysis of the source-built Microsoft components. Done**
([record](source-built-component-assessment.md)). The bulletin index found 8
LSASS, 0 SCM, 0 effective Winsock, 36 win32k and 15 GDI/USER bulletins affecting
XP after 1106. Six defects were located in our source and fixed
(win32k ×4, user32, gdi32). Three LSASS and dozens of win32k/GDI bulletins
remain *suspected*: Microsoft never published their mechanisms.
**R-1b** locates those by comparing the 1106 binaries with Microsoft's final XP
builds function by function, and assesses the kernel and CSRSS. The original
item: Milestone 8.4
analyzed XP25's own code only. For the 25 rebuilt Microsoft binaries, start
with the ones that face untrusted input and run privileged: `lsasrv.dll`
(partly done in 8.2), `services.exe`, `ws2_32.dll`, `win32k.sys`. No CL-compatible
static analyzer exists in the tree (PREfast is absent); use targeted review and
host-side ASan harnesses for portable routines, as 8.2 did for CVE code.
*Done when* each has a recorded assessment and any confirmed defect has a fix and
a guest proof.

**R-2 — `/GS` for the remaining XP25 binaries, then the Microsoft user-mode
builds.** Winlogon: add `BUFFER_OVERFLOW_CHECKS=1` and run the Winlogon
lifecycle harness (18 gates, UP/MP/TCG) plus the account-switch oracle.
XP25Sec/XP25Audit: their custom entry points skip the CRT start-up, so call
`__security_init_cookie` first. Then evaluate the 25 Microsoft builds: user-mode
DLLs can use the same library (`ntdll` itself needs `BUFFER_OVERFLOW_CHECKS=NO_NTDLL`,
as some original components do). No kernel-mode GS library is in the tree.
SafeSEH needs a 7.1 linker, which the tree does not have. *Done when*
`build/gs_check.py` passes for each binary and its regression suite passes.

**R-3 — Free (retail) builds of the source-built core.** The kernel, HAL,
`win32k.sys`, `ntdll.dll`, `kernel32.dll` and others ship as checked builds:
asserts, debug output and no optimization. This is likely the largest
performance lever in XP25. It is also the riskiest change: earlier milestones
hit checked/free HAL mismatches. *Done when* a full free set boots and passes
the security matrix, the compatibility suite and the recorded game workloads,
with boot and desktop timelines compared using the serial timeline added in 8.4.

**R-4 — RoverAI search and memory behaviour.** Replace the per-position
`xp25_strnieq` call in `xp25_stristr` with a fold table and a first-character
scan. Use a differential test like `tests/rover_index_diff.c` and the search
phase of `tests/rover_bench.c`. Investigate why a second scan in the same
process is slower in the guest (heap reuse after freeing about 600,000 blocks is
the first suspect; measure with the phase probe). Replace the linear duplicate
check in `rover_words_from_text` only if a measurement shows it matters.

**R-5 — One IPC sender and correct quoting.** Make `xp25w_clippy_request`
build the `WM_COPYDATA` message through one helper that ClippyAI's
`forward_to_existing` also uses. Quote launch arguments by
`CommandLineToArgvW` rules: double backslashes before a quote, escape quotes.
Test with a value ending in `\` and one containing quotes.

**R-6 — RoverAI watcher lifecycle.** Either make watcher scans cancellable
(`ROVER_SCAN_CONFIG.cancelled` from the stop event), join the threads before
freeing and take the store mutex before the lock in `background()`, or remove
the stop path, which nothing reaches today, and correct its comment. A guest
test should post `WM_QUIT` to the indexer during an overflow rescan.

**R-7 — Broker edge cases.** After `CancelIo`, wait for the overlapped connect.
Treat a failed `CreateEventW` as a start failure, reported the way a stolen pipe
name is.

**R-8 — Separate the RoverAI engine.** Build `rover_index.c`, `rover_query.c`
and `rover_win.c` as a static library that `xp25agent.dll` links, keeping its
`.def` exports. This removes the source-level cycle without an ABI change.

**R-9 — Winlogon notification policy.** Decide whether a broken notification
package should stop the others (today's fail-closed behaviour) or be logged and
skipped (the original Winlogon). Test with a registered package whose DLL is
missing.

**R-10 — Split the largest functions** behind tests that pin current
behaviour: RoverAI's natural-language parser, the offline planner's network
analysis, XP25Sec's `apply` and `rollback`.

**R-11 — Shared lab core.** `security_lab.py`, `ai_lab.py`, `network_lab.py`
and `winlogon_switch_probe.py` each implement overlay creation, staging, QMP
and shutdown checks. Extract one module with its own tests. The harnesses are
evidence-critical, so every existing role must give identical gate results
before and after.

**R-13 — Crash evidence on engineering images.** The images write no crash
dump, and the checked kernel restarts automatically after a bugcheck. A guest
reset without shutdown records therefore leaves nothing to analyze, as in
`runs/m84-std-tcg-01`. Enable small memory dumps (and keep `AutoReboot`, or turn
it off for diagnostic runs) in lab overlays, and have the results tools collect
`\WINDOWS\Minidump`.

**R-12 — Python hygiene.** Remove the 13 unused imports and locals reported by
pyflakes.

**Also carried from Milestone 8:** Windows File Protection hosting with a catalog
of the source-built files; `InitShutdown` so `shutdown.exe` works; a password and
a standard account as the daily default. The account-switch fix is in an
engineering image, not yet in an accepted one.
