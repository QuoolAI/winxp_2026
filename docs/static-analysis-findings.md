# Static analysis findings (Milestone 8.4)

Worktree `xp25-modernization`, from the accepted line at `a77550aa6` (Milestone
8.2 plus the Winlogon account-switch fix). Evidence root
`.work/modernization-20261118/` (`M`). Related:
[architecture audit](architecture-modernization-audit.md),
[optimization opportunities](optimization-opportunities.md),
[roadmap](modernization-roadmap.md).

**Scope.** This document covers every XP25-authored C file (126 files under
`components/` and `tests/`) and the Python tooling (128 files). It does not
cover the 277,863-file Microsoft reference tree under `Source/`, which is
preserved, not refactored. Automated scanning is a first pass: it located code
for manual review and established nothing by itself. Each finding below names
the evidence that classifies it.

## Tools evaluated

| Tool | Available | Used for | Notes |
| --- | --- | --- | --- |
| NT CL 13.00.9176 `/W4 /WX` (guest build) | Yes | Every native target, unchanged gate | The authority for the shipped binaries. It rejected a function-to-data pointer cast (C4054) that MinGW accepted (native build `m84-ai-native-15`, kept) |
| PREfast / `/analyze` | **No** | — | Not in the 5.1.2600.1106 `tools` tree; CL 13 has no `/analyze` |
| MinGW-w64 GCC 13 (i686), `-Wall -Wextra -Wshadow -Wformat=2 -Wcast-qual -Wconversion -Wsign-conversion -Wnull-dereference -Wlogical-op …` + `-fanalyzer` | Yes | 71 translation units of the 8 native targets with NT 5.1 defines | MinGW headers are not the NT 5.1 SDK; a diagnostic is a lead, not a property of the CL-built binary |
| Host GCC 13 `-fanalyzer` | Yes | Portable cores (Winlogon state/policy/session engine/environment/boot key codec, security core, agent runtime, RoverAI index/query) | 0 diagnostics |
| AddressSanitizer + UndefinedBehaviorSanitizer | Yes | Existing host tests (134), new fuzzing and differential tests | |
| gcov | Yes | Fuzzing coverage | |
| gprof | Yes | RoverAI benchmark profile | `perf` is restricted on this host (`perf_event_paranoid` 4) |
| pyflakes, pylint | Yes | Python tooling | pylint not used beyond availability; pyflakes results below |
| cppcheck, clang-tidy, clang static analyzer, semgrep, flawfinder | **No** | — | Not installed; not downloaded (no unvetted tools added to the host) |

Commands (from the worktree root):

```sh
python3 build/modernization_inventory.py --output M/inventory-01
python3 build/static_analysis.py --output M/static-01 --toolchain <main tree>/.work/toolchains/mingw-binutils/usr/bin
cc -std=c89 -pedantic -Wall -Wextra -Werror -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
   <includes> tests/fuzz_parsers.c <portable sources> -o M/fuzz-01/fuzz_parsers   # see tests/test_modernization.py
M/fuzz-01/fuzz_parsers 3000000 0x1111   # also 0x2222, 0x3333
```

## Results

**Compiler and analyzer pass** (`M/static-01/findings.json`, 71 units compiled,
0 failed): 120 distinct diagnostics.

| Rule | Count | Classification |
| --- | --- | --- |
| `-Wsign-conversion` | 44 | False positive / benign: `lstrlenW` results stored in `size_t`, `~DBIM_BKCOLOR` bit clears, the Winsock `FIONBIO` constant; six sampled sites read in full |
| `-Wcast-qual` | 21 | Benign: read-only data passed to Win32/WLX parameters declared without `const` |
| `-Wdiscarded-qualifiers` | 18 | Benign, same cause (MSGINA's `WLX_*` dispatch, `ReportEventW`, `CreateProcessW`) |
| `-Wmisleading-indentation` | 16 | Style only: the Winlogon sources put several statements on one line; no control-flow defect found in the 16 sites |
| `-Wcast-function-type` | 4 | Inherent to `GetProcAddress`; no change |
| `-Wanalyzer-fd-leak` | 2 | False positive: Winsock `SOCKET`s closed with `closesocket`, which GCC models as a POSIX descriptor (`xp25_http.c:158`, `win_network.c:87`) |
| `-Wanalyzer-null-dereference` | 1 | False positive: `policy_native.c:77`, COM's contract that `S_OK` returns a non-NULL interface |
| `-Wanalyzer-use-of-uninitialized-value` | 1 | False positive: `xp25_sha256.c:26`, the message schedule fills `w[0..15]` then computes `w[16..63]` in order |
| pyflakes | 13 | Confirmed, harmless: unused imports/locals in `build/` and `vm/` scripts (listed in `M/static-01/pyflakes.log`); not changed, to keep this milestone free of unrelated edits |

The portable cores produced **no** diagnostic under the host analyzer.

**Sanitizer fuzzing** (`tests/fuzz_parsers.c`, `M/fuzz-01`): eight targets that
receive data across a trust boundary, each driven from a seed corpus by a
fixed-seed mutator, with round-trip properties checked. Three campaigns (seeds
`0x1111`, `0x2222`, `0x3333`) of 3,000,000 inputs per target (750,000 for the
index file, which is re-sealed after mutation so its checksum does not stop the
parser): **0 sanitizer reports, 0 property failures.**

| Target | Input in the product | Property checked | Line coverage (`M/fuzz-cov-01`, whole file) |
| --- | --- | --- | --- |
| `xp25_json_parse` and accessors | broker requests from any interactive user (parsed by SYSTEM), model and gateway responses, IPC | parse → write → parse → write is stable | `xp25_json.c` 99.5% |
| `xp25_llm_parse_response` | gateway / OpenAI-compatible responses | no crash, reply freed | `xp25_llm.c` 36.7% (request builders not fuzzed) |
| `rover_query_parse`, `rover_criteria_from_json` | typed searches, model-produced criteria | no crash | `rover_query.c` 68.1% |
| `rover_index_deserialize` | `%LOCALAPPDATA%\XP25\RoverAI\index.dat` | a loaded index reserializes and reloads | `rover_index.c` 31.9% (scanning is not a parser) |
| `xp25_analyze_network_text`, `xp25_offline_intent`, `xp25_offline_path` | file content and requests read by the offline assistant | no crash | `xp25_offline.c` 18.4% (planner not fuzzed) |
| `xp25_policy_*`, `xp25_utf8_clip` | every agent tool call | no crash | `xp25_policy.c` 94.4%, `xp25_base.c` 91.4% |
| `sec_backup_parse` | XP25Sec rollback records | parse → format → parse is identical | `sec_core.c` 48.2% (rule tables) |
| `wl_environment_next/find`, `wl_decode_boot_classes` | user environment block, SYSKEY registry classes | no crash | `environment.c` 100%, `bootkey_codec.c` 95.2% |

## Findings

Severity is for XP25 as shipped (an administrator desktop on an isolated
network). Classification: **confirmed** (shown by evidence named),
**suspected**, **false positive**, **requires runtime verification**.

| ID | Component | Finding | Evidence | Classification | Severity | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SA-0 | Winlogon | USER's screen-saver notice (`LOGON_INPUT_TIMEOUT`) is not handled: no screen saver ever starts, so once the screen-saver timeout passes USER re-posts it on every idle tick (about twice a second, `IdleTimerProc` → `StartScreenSaver`, `windows/core/ntuser/kernel/input.c`) for as long as the session is idle. Winlogon logged each notice twice, opening the exclusive COM1 port for every line and appending to `C:\xp25\native-winlogon.log` | Found while profiling: the TCG benchmark's probes could not write to COM1 after 10 idle minutes (`runs/m84-rover-phases-tcg-01`, 4,768 notices logged in 40 min). Idle probe on the 8.2 image's Winlogon: COM1 openable for 70 of 110 attempts, log growth 23,520 bytes per idle minute (`runs/m84-idle-wlold-up-01`) | **Confirmed** | Medium (serial devices and diagnostics blocked; ~34 MB of log per idle day; no idle lock even with a password-protected screen saver) | **Fixed** for the logging (build `289abb03…`: 104/104 COM1 opens, 0 bytes per idle minute, one record per idle period); screen savers themselves remain unsupported: roadmap R-0 |
| SA-1 | ClippyAI | Exit while an approval or sharing question is open: `WM_DESTROY` runs inside the dialog's modal loop, waits 15 s for the worker, which is blocked in `SendMessage` to this same thread, then frees the agent, tools and provider. The worker resumes on that freed state once the dialog unwinds | Guest probe `clippyexit` on build 14: exit took 15,063–15,187 ms in 3/3 cycles (`runs/m84-clippyexit-b14-up-01`), and 15,062–15,094 ms with full page heap (`-ph-b14-`) | **Confirmed** (hang, deterministic); use after free confirmed in code, not observed as a crash even under page heap (process exit wins the race) | Medium | **Fixed** (build 16: 94 ms) |
| SA-2 | RoverAI Explorer bar | The search thread runs `RoverAIBand.dll` code inside Explorer without a module reference; `DllCanUnloadNow` counts only COM objects and locks, so closing the bar during a search lets COM unload the DLL under the thread | Code: `panel.c` `start_search`/`search_thread`, `band.c:364` | **Confirmed** in code; the unload crash was **not reproduced** at runtime | Medium (crash of Explorer) | **Fixed** (thread holds its module, ends with `FreeLibraryAndExitThread`) |
| SA-3 | RoverAI background indexer | `rover_watch_stop` waits 10 s per watcher thread, then frees state a thread still mid-scan uses; `background()` takes the index lock before the store mutex, the reverse of the documented order | Code: `rover_win.c:538-551`, `main.c:140-143` | **Latent**: unreachable as shipped. Nothing posts `WM_QUIT` to the windowless indexer (logoff terminates it); the inversion cannot deadlock because no watcher can be dirty before the first reconcile releases the lock. The comment "logoff (WM_QUIT/end session) ends the indexer cleanly" is inaccurate | Low | Roadmap R-6 |
| SA-4 | XP25Broker | After `CancelIo` on the stop event, `serve()` does not wait for the cancelled `ConnectNamedPipe` before its stack `OVERLAPPED` goes out of scope | Code: `broker.c:312` | **Suspected benign** (the IRP completes during `CloseHandle` on the same thread) | Low | Roadmap R-7 |
| SA-5 | XP25Broker | If `CreateEventW` fails for the stop event or the `OVERLAPPED`, `serve()` spins | Code: `broker.c:304-317, 328` | **Requires runtime verification** (resource exhaustion only) | Low | Roadmap R-7 |
| SA-6 | RoverAI → ClippyAI launch | `xp25w_clippy_request` quotes the value without escaping: a trailing backslash (`C:\`) or an embedded quote is re-split by `CommandLineToArgvW` | Code: `xp25_ipc_win.c:38-41`; `CommandLineToArgvW` rules | **Confirmed** by the API's rules (not run) | Low (same user, functional) | Roadmap R-5 (with SA-12) |
| SA-7 | Winlogon notifications | The first notification package that fails (missing DLL or export) stops the remaining packages for that event; the original Winlogon logs and continues | Code: `notify.c:109-160` | Design difference (fail-closed), not a defect | Info | Documented; decision in roadmap R-9 |
| SA-8 | Agent file policy | `xp25_policy_file` is safe only with canonical paths; `win_files.c` canonicalizes with `GetFullPathNameW` and the long form first, which removes `/`, `.\`, trailing dots and 8.3 names | Code review | Contract holds today; the header says "already-canonical" | Info | No change |
| SA-9 | All XP25 binaries | No `/GS` stack cookies (the NT build supports `BUFFER_OVERFLOW_CHECKS`; 19 original components use it) | Build 14 binaries contain no GS support code | **Confirmed** | Hardening | **Fixed for the 5 AI targets** (build 17, 162 protected epilogues); Winlogon, XP25Sec, XP25Audit: roadmap R-2 |
| SA-10 | RoverAI index | Logon rescan dominated by full-index binary searches of long shared path prefixes, folded one character per call | gprof (`M/bench-01`); benchmark | **Confirmed** (performance) | — | **Fixed**, measured (see [optimization](optimization-opportunities.md)) |
| SA-11 | RoverAI search | `xp25_stristr` calls `xp25_strnieq` at every haystack position (220 million calls for one content query on the synthetic tree) | gprof | **Confirmed** (performance) | — | Roadmap R-4 |
| SA-12 | ClippyAI / agent IPC | `forward_to_existing` (ClippyAI) duplicates the `WM_COPYDATA` sender of `xp25w_clippy_request` | Inventory duplicate windows | **Confirmed** duplication | Low | Roadmap R-5 |
| SA-13 | `rover_words_from_text` | Linear duplicate check per word (≤512 × 2048 comparisons per file) | Code | Confirmed, minor | Low | Roadmap R-4 |
| SA-14 | Python tooling | 13 unused imports/locals | pyflakes | Confirmed, harmless | — | Roadmap R-12 |

**Concurrency.** Threads exist in Winlogon (notification workers, local fonts,
boot key worker, shell desktop check), RoverAI (watchers per root, Explorer bar
searches), ClippyAI (agent worker), the browser `pwrp_k32` proxy (issuer
thread) and XP25Broker (single-threaded service loop). Lock order is consistent
everywhere except SA-3. Shared counters use `Interlocked*`. The two
thread-lifetime defects (SA-1, SA-2) are fixed. No data race was found in the
reviewed paths. There is no XP25-authored kernel-mode code, so IRQL, pool type
and unload rules did not apply. The only kernel change in the product, the
`KeFlushQueuedDpcs` export added in Milestone 8, is a relink of Microsoft's
source.

**Runtime behaviour found by measurement.** SA-0 was not visible to any static
tool. It appeared only when a benchmark left the guest idle past the
screen-saver timeout. The serial timeline added in this milestone made the
notice rate measurable.

**Memory safety.** No buffer overflow, integer overflow, double free or
uninitialized read was confirmed in XP25 code by fuzzing, sanitizers or review.
The one confirmed use after free (SA-1) is a lifetime defect, now fixed. The
parsers that see untrusted input bound every read (reviewed:
`xp25_json.c`, the HTTP chunk decoder in `xp25_http.c`, `rover_index_deserialize`,
`broker.c` request handling).

## Limitations

* MinGW headers stand in for the NT 5.1 SDK in the native pass; CL's own `/W4`
  remains the build gate.
* No dedicated C static analyzer (cppcheck/clang) was available.
* Fuzzing covers the portable parsers only; Win32 adapters were reviewed by
  hand. SA-2's crash and SA-1's use after free were not observed at run time.
* The Microsoft components built from `Source/` were not statically analyzed
  in this milestone (see roadmap R-1/R-3).
