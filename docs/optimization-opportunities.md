# Optimization opportunities (Milestone 8.4)

Evidence root `.work/modernization-20261118/` (`M`). Companion documents:
[architecture audit](architecture-modernization-audit.md),
[static analysis](static-analysis-findings.md), [roadmap](modernization-roadmap.md).

The rule for this milestone: no change is accepted because an algorithm looks
faster. A change needs a measured baseline, an equivalence test and a measured
result, on the host and in the guest.

## What was measured

| Area | Method | Baseline observation |
| --- | --- | --- |
| Boot to logon prompt, logon, desktop start | Host-side serial timeline (`vm/security_lab.py wait` now writes `serial-timeline.jsonl`: first sighting of each Winlogon event and fixture marker, 2 s poll) and the QMP journal | See [Start-up timeline](#start-up-timeline) |
| RoverAI index (logon reconcile, full scan, load/save, notifications) | Host benchmark `tests/rover_bench.c` on a synthetic 277,665-entry tree (median of 5, alternated builds), `gprof`; in-guest phase probe `roverbench_probe.exe` on the engineering image's real C: (315,857 entries) | Rescan slower than a full scan on the host (1.85 s vs 1.05 s) |
| RoverAI search | Same benchmark, five queries | 0.6–297 ms; one content query dominated by case-insensitive substring search |
| ClippyAI exit | `clippyexit` probe | 15.06–15.19 s whenever a question was open (a defect, see static analysis SA-1) |
| `/GS` overhead | Phase probe build 16 vs build 17 | See below |

Not measured in this milestone: service start order and per-service time,
process creation cost, registry access patterns, network throughput and lock
contention profiles. The tools exist (`vm/inspect_threads.py`,
`vm/capture_memory.py`, the network probe), but no performance change in those
areas was proposed, so no baseline was taken.

## RoverAI index reconcile (implemented)

**Existing implementation.** The index is a sorted array of entries
(case-insensitive path order) with binary search. A rescan walks every
directory; for each listed child it built the full path with two allocations
and looked it up with `rover_index_find`, a binary search of the whole index.
On a 300,000-entry index each lookup is about 18 comparisons of long paths that
share most of their prefix. Each comparison folded case one character at a
time through an out-of-line `xp25_lower` call.

**Profile** (`gprof`, `M/bench-01`): 2.86 billion `xp25_lower` calls and
8.4 million `rover_path_compare` calls in one benchmark run. Folding alone
accounted for 46% of samples.

**Change** (`components/roverai/indexer/rover_index.c`, ABI unchanged):

1. A directory's subtree is contiguous in the index and in the same order as its
   sorted listing: both sort by `rover_path_compare`, and every path in it starts
   with the directory's prefix. The listing is therefore matched by moving one
   cursor forward through that range and comparing names only.
2. `rover_path_compare` folds ASCII inline, and only where the bytes differ.
   The result is identical: `xp25_lower` folds `A`–`Z` only.
3. The child path is built from the prefix already computed (one allocation
   instead of two).

**Equivalence.** `tests/rover_index_diff.c` builds the pre-8.4
`rover_index.c` (from git, symbols renamed) beside the new one. It drives both
through 900 rounds of randomly changing file systems: names chosen to reorder
under case folding (`[ ] _ ^ \``, `A`–`Z`), characters either side of `\`, high
bytes, case-only renames, moves, deletions, denied, missing, reparse and
excluded directories, entry limits, content indexing, full and incremental
scans and change notifications. **Saved indexes are byte-identical and scan
statistics identical.** Two of three deliberately planted bugs were detected
(1,393 and 2,100 mismatches). The third removed the `DEAD` check from the cursor
match and is unobservable: a dead entry inside a subtree always has a name the
listing lacks. The check is kept for parity with `rover_index_find`.

**Host results** (median of 5 runs, builds alternated twice, `-O2`;
`M/bench-01/before-after-host.log`):

| Phase | Before | After | Change |
| --- | --- | --- | --- |
| Rescan with nothing changed (the logon reconcile) | 1,848 / 1,866 ms | 436 / 443 ms | **−76% (4.2×)** |
| Full scan of an empty index | 1,048 / 1,046 ms | 437 / 446 ms | −58% |
| Load (deserialize, order check) | 311 / 314 ms | 242 / 250 ms | −22% |
| 2,000 change notifications | 84 / 85 ms | 76 / 82 ms | ≈ −6% |
| Content search "text files containing network" | 297 / 298 ms | 294 / 305 ms | unchanged (not targeted) |

**Guest results**, one-vCPU KVM, the 8.2 image's real C: (315,857 entries,
25,414 directories). Phase probe, builds alternated in three rounds, nothing
saved (`runs/m84-rover-phases-up-02`):

| Build | Scan, first repeat per process (ms) | Scan, second repeat (ms) | Load (ms) | Serialize (ms) |
| --- | --- | --- | --- | --- |
| 14 (accepted) | 2,719 / 2,687 / 2,594 — median **2,687** | 3,734 / 3,828 / 3,813 | 281–765 | 218–360 |
| 16 (this change) | 2,125 / 2,156 / 2,078 — median **2,125** | 4,625 / 3,782 / 3,031 | 250–766 | 219–359 |
| 17 (+ `/GS`) | 5,281 / 2,109 / 2,094 — median **2,109** | 3,421 / 9,563 / 3,016 | 265–828 | 219–359 |

In the guest the scan is dominated by the native directory listing (25,414
`FindFirstFile`/`FindNextFile` enumerations). The portable work this change
targets saves about **560 ms per rescan (−21%)** under KVM. The second scan
inside one process is slower and noisier for every build; it was not
investigated (roadmap R-4). The guest-side times of the earlier whole-command
comparison (`RoverAI.exe /index`, `runs/m84-rover-ab-b16-up-01`) are kept but
not used: they include writing and flushing a 24 MB file and varied from 3.9 to
15.8 s for the same build.

**Guest results under TCG** (one emulated CPU; same probe). No saved index
existed in these overlays: the background indexer had not finished its first
index when the fixture stopped it. Every repeat is therefore a **full scan**
(315,857 entries added), the phase whose host saving is −58%.

| Run | Build 14 scan (ms) | Build 16 scan (ms) | Build 17 scan (ms) |
| --- | --- | --- | --- |
| `m84-rover-phases-tcg-01` rounds 1–2 (round 3 lost, see below) | 69,109 / 46,078 / 43,641 / 46,703 (+ round 3: 45,172 / 46,672) — median 46,375 | 47,734 / 44,047 / 36,031 / 39,000 — median 41,524 | 37,187 / 39,391 / 35,922 / 39,453 — median 38,289 |
| `m84-rover-phases-tcg-02` (8.4 Winlogon, all three rounds) | 66,218 / 47,219 / 42,938 / 46,453 / 42,641 / 45,625 — median **46,039** (first repeats 42,938) | 43,500 / 46,718 / 35,828 / 38,813 / 35,672 / 39,625 — median **39,219** (first repeats 35,828) | 36,156 / 40,172 / 36,219 / 38,312 / 36,062 / 38,235 — median **37,227** (first repeats 36,156) |

Under TCG the full scan is about **15% faster** with the change (median of six:
46.0 s → 39.2 s; first repeats 42.9 s → 35.8 s). The first scan after logon
(66–69 s for build 14 in both runs) includes cold file-system caches and is
included in the medians. Serialization took 1.17–1.70 s for every build. The
logon reconcile, a rescan against a saved index, was not measured under TCG;
the host and KVM rescan results above stand for it. Round 3 of `tcg-01` was lost
to a Winlogon defect that this milestone then fixed (static analysis SA-0).
Once the guest had been idle for ten minutes, Winlogon's logging of repeated
screen-saver notices kept COM1 busy, and the probes could not report (the run
is kept with `failure.json`).

## `/GS` cost

Build 17 differs from build 16 only by `BUFFER_OVERFLOW_CHECKS=1`. The binaries
grow by 512 to 3,072 bytes (`xp25agent.dll` 155,136 → 158,208). The scan phase,
which runs mostly inside `xp25agent.dll`, shows no measurable difference
(first-repeat median 2,109 vs 2,125 ms).

## Start-up timeline

`vm/startup_timeline.py` reads the run's `serial-timeline.jsonl` and QMP
journal. Times are seconds after the guest was resumed, at the timeline's 2 s
granularity. "Logon submitted" is when the lab typed the password; the lab
waits about 9 s after the prompt appears, which is harness latency, not the OS.

| Run (image 8.2) | Mode | Winlogon started | Logon prompt ready | Password typed | Interactive session | Logon → interactive | Desktop Startup fixture |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `m84-idle-wlold-up-01` (8.2 Winlogon) | KVM, 1 vCPU | ≤ 10.1 | ≤ 12.1 | 21.3 | ≤ 25.3 | ≤ 4.0 | ≤ 25.3 |
| `m84-idle-wlnew-up-01` (8.4 Winlogon) | KVM, 1 vCPU | ≤ 10.1 | ≤ 12.1 | 21.3 | ≤ 25.3 | ≤ 4.0 | ≤ 25.3 |
| `m84-gscookie-up-02` (build 17, 8.4 Winlogon) | KVM, 1 vCPU | ≤ 10.1 | ≤ 12.1 | 21.3 | ≤ 25.3 | ≤ 4.0 | ≤ 25.3 |
| `m84-rover-phases-tcg-01` (8.2 Winlogon) | TCG | ≤ 20.1 | ≤ 30.1 | 79.4 | ≤ 89.4 | ≤ 10.0 | ≤ 91.4 |

The regression matrix (build 17 and the 8.4 Winlogon) gives the same picture:

| Runs | Mode | Winlogon started | Logon prompt ready | Logon → interactive |
| --- | --- | --- | --- | --- |
| `m84-proof-up-01`, `m84-fw-up-01` | KVM, 1 vCPU | ≤ 10.1 | ≤ 12.1 | ≤ 4.0 |
| `m84-proof-mp-01`, `m84-fw-mp-01` | KVM, 2 vCPU | ≤ 10.1 | ≤ 12.1 | ≤ 4.0 |
| `m84-ai-load-up-01` (host load: 4 busy processes + disk writer) | KVM, 1 vCPU | ≤ 14.1 | ≤ 20.1 | ≤ 4.0 |
| `m84-ai-load-mp-01` (same load) | KVM, 2 vCPU | ≤ 12.1 | ≤ 20.1 | ≤ 16.0 |
| `m84-proof-tcg-01`, `m84-fw-tcg-01` | TCG | ≤ 18.1–20.1 | ≤ 28.1–30.1 | ≤ 8.0–10.0 |

Reading: at this resolution, Winlogon's own start-up (secure desktop, SYSKEY,
LSA, MSGINA negotiation and initialization) fits within 2 s under KVM. A logon
reaches the interactive desktop within 4 s, covering profile load, the identity
checks, licensing admission and shell start. Most of the time to the logon
prompt passes before Winlogon starts: firmware, loader, and the kernel, Session
Manager and CSRSS start-up. Those run the **checked** source builds and are not
instrumented by this timeline (roadmap R-3). The Milestone 8.4 Winlogon change
does not alter any of these times.

## Opportunities not taken

| Opportunity | Evidence | Why not now |
| --- | --- | --- |
| Case-insensitive substring search in RoverAI (`xp25_stristr`: 220 million `xp25_strnieq` calls for one content query on the synthetic tree) | gprof | Needs its own equivalence test and guest measurement; roadmap R-4 |
| Second-scan slowdown within one process (heap reuse after freeing 600,000 blocks?) | Guest phase probe | Not yet understood; roadmap R-4 |
| Free (retail) builds of the 25 source-built Microsoft components, which ship as checked builds | Milestone 8 audit | Would change every core binary; needs a full boot, compatibility and game baseline; roadmap R-3 |
| Duplicate-word check in `rover_words_from_text` | Code | Minor (≤ 1 ms per file); roadmap R-4 |
