# Milestone 7A: offline Supermium integration — GPU investigation, stability, status

Continues the `xp25-browser` worktree; offline scope only (Internet-facing
security is Milestone 7B). Private evidence under `.work/browser-fix-20261026/`
(abbreviated `X`); no host paths or secrets are committed. Each test below is
classified PASS / FAIL / SKIPPED / NOT TESTED; unexecuted tests are never reported
as passes.

## GPU-process instability (0x842214): investigation and configuration decision

The remaining intermittent CHECK is `base::win::TakeHandleOfType(handle,"Section")`
failing (`scoped_handle.cc:77`) while a child parses its inherited
`--field-trial-handle` (field-trial read-only shared-memory Section). Every
*previously* captured instance was in the `--type=gpu-process` child, which
motivated testing whether a GPU configuration avoids it.

A controlled A/B (`X/collect-gpuab-01`, 12 debugger cycles each on XP25 KVM,
software rendering) compared the shipping default against `--in-process-gpu`:

| Config | gpu-process spawned | 0x842214 CHECKs | failed cycles | JS receipts |
| --- | ---: | ---: | ---: | ---: |
| `--disable-gpu` (default) | 27 | 0 | 0/12 | 12/12 |
| `--disable-gpu --in-process-gpu` | 0 | 14 | 0/12 | 12/12 |

**Finding: no GPU configuration avoids the crash.** `--in-process-gpu` does remove
the separate GPU process, but the CHECK simply **relocates** — it fired 14 times in
`--type=utility` and `--type=renderer` children instead (first + second chance;
those children exit `0x80`). The default config happened to hit it zero times this
run, confirming the failure is **intermittent** and tied to the field-trial Section
handle inheritance common to *all* child types, not to the GPU process specifically.
In both configs every cycle still rendered (12/12 JavaScript receipts) and the root
process exited cleanly, so in these runs the dying process was a spare child the
browser does not need for the page; but a prior capture (`fab150-sp3-up-01` dprox1)
showed a cycle where the root itself exited `0x80`, so the crash **can** be fatal.

**Decision:** keep the existing **`--disable-gpu` software-rendering** default
(already the shipping configuration via the `SoftwareRendering` DWORD and the
`XP25Browser.exe` launcher). `--in-process-gpu` is **rejected**: it gives no
stability benefit and exposed the CHECK more. No assertion is suppressed, no handle
type is fabricated, and the NT kernel is unchanged. Per the milestone, because the
intermittent crash remains reproducible, the offline browser keeps the
**experimental** designation and 0x842214 is documented as the outstanding blocker
(root cause and prior analysis: `browser-stability-security.md`,
`browser-security-7b.md`; it reproduces on stock XP SP3 and is a Supermium/Chromium
gpu/child handle-lifetime defect with no safe fix at the `pwrp_k32` layer).

Software rendering was confirmed functional throughout (HTML, CSS, modern
JavaScript and window rendering; receipts in every cycle). DevTools-driven video
and scroll checks were not separately scripted here; the KVM functional regression
(`matrix-150-02`) already exercised rendering, multi-tab and downloads.

## Stability regression (repeated launch/navigate/close)

Unmonitored loop (no debugger observer), shipping `--disable-gpu` config, isolated
local test server, software rendering. A root exit ≠ 0 in a cycle is a critical
crash.

| Test | Result | Evidence |
| --- | --- | --- |
| Single-vCPU KVM, 20 launch/navigate/close cycles | **PASS** — 20/20 cycles, 0 failed, 20 JS receipts, shell checks pass | `X/runs/fstab-up-01` |
| Two-vCPU KVM, 20-cycle loop | **PASS** — `fstab-mp-04` (2026-10-28), MP kernel/HAL base `582d551d`, −smp 2, ~26 GB host free: **20/20 `PLAIN_CYCLE_EXIT root_code=00000000`**, **0** non-zero process exits across 157 child/root exits, **0** `0x842214`/CHECK/crash, **13/13 shell checks PASS**, and a genuine guest-initiated clean shutdown (`{"guest":true,"reason":"guest-shutdown"}`, checkpoint `normal_shutdown_frozen`, disk `49de458a…`). (`0x842214` is intermittent — it fired 0 times in this loop but is not resolved; the experimental designation stands.) **Correction:** the earlier `fstab-mp-01/02/03` attempts did NOT test this loop and their "host-contention" notes were wrong — the real cause was an operator base-image error: they ran `--mode mp` (−smp 2) against the **UP** image `ec22f45b`, whose uniprocessor HAL BSODs at early boot under two vCPUs. This was proven by `fstab-mp-03` reproducing the identical 640×480 boot halt with ~26 GB host RAM free. The correct MP base is the MP kernel/HAL image `582d551d` (the same base `finstall150-01` and the passing `matrix-150-02` regression used). The three superseded attempts are frozen with corrected `failure.json`. | `X/runs/fstab-mp-04` (PASS); `fstab-mp-01/02/03` (superseded, corrected) |
| KVM UP+MP full functional regression (JS, HTML, multi-tab, HTTPS cert matrix, download, policy, profile+appearance persistence, AI cases, shutdown) | **PASS** (prior checkpoint) | `X/matrix-150-02`, `browser-stability-security.md` |
| TCG practical offline functional (launch, local render, all 5 ShellExecute document types, basic navigation, shutdown) | **PASS** (non-DevTools path; DevTools automation is emulation-speed-limited, documented) | `X/runs/fmatrix150-02-tcg`, `fmatrix150-03-tcg` |

The persistent directory-watcher I/O worker (watcher proxy) showed clean teardown
across these repeated cycles and the `browser_watch` probe (32/32 concurrent
exited-issuer watches); no watcher CHECK occurred.

## Integration and offline configuration

Browser integration (desktop/Start-menu/Quick-Launch shortcuts, default-browser
registration, http/https/.htm/.html/.url associations, ShellExecute, Explorer link
opening, downloads, multiple windows, profile persistence, restart, rollback) was
verified in the KVM functional regression and the shell/containment runs; IE is
hidden from the user-facing browser selection while MSHTML/WinINet/URLMon/Shdocvw/
BrowseUI are retained (Trident-dependent Help is a documented follow-up, not
removed). Offline configuration holds: no `--remote-debugging-port` or test bridge
in the install image, TLS verification on, no certificate-bypass flags, the
`URLBlocklist=*` default policy, the restricted-token + job launcher preserved, and
profile data confined to the guest by the restricted token.

## Accepted offline engineering image

**PRODUCED and cold-boot verified (2026-10-28), experimental.** The image was built
once host memory recovered (the large non-browser VM exited; ~26 GB free), one guest
at a time:

1. **Fresh clean install** — `X/runs/offline-install-01`, `--mode up` on the MP
   kernel/HAL base `582d551d` (so the image boots both UP and MP), clean media
   `X/prepared-150-05/browser.iso` (`7c604b95…`: software-rendering, `URLBlocklist=*`,
   no remote-debugging bridge; Supermium 150 R2.01 pin `d9a06a6c…`). Result:
   `XP25_IMAGE_INSTALL_EXIT=0`; the launcher rejected a `javascript:` URL, an extra
   argument and a non-HTML target (each `=87`); genuine guest-initiated shutdown
   (`{"guest":true}`, `normal_shutdown_frozen`, disk `f46487ce…`).
2. **Package** — `python3 vm/package_browser_image.py --run …/offline-install-01
   --prepared …/prepared-150-05 --output …/offline-image-01`. It re-verified **292
   installed Supermium/launcher file hashes** against the prepared manifest and the
   `installed.ok` marker against the pin, then `qemu-img convert -c` → `check` →
   `compare` (bit-exact) → `info`. Output:
   **`X/offline-image-01/XP25-Browser-Experimental.qcow2`**, 3,591,766,016 bytes
   (32 GiB virtual, 3.58 GiB actual), standalone **no backing file**, read-only,
   SHA-256 **`6cad84c6c39e056e24bb84165665e0c47bbf13ec1e433d0de43c3b37a63b101f`**,
   manifest `status=experimental_unaccepted`, `acceptance_complete=false`.
3. **Cold-boot verification** — `X/runs/offline-coldboot-01`, a fresh overlay of the
   produced image with no install media action (verify suite only, no reinstall, no
   network). The standalone image booted NT 5.1 independently and passed **15/15
   shell cases, `XP25_BROWSER_SHELL_FAILURES=0`** (http/https/.htm/.html/.url +
   legacy htmlfile/htmfile associations to `\XP25Browser\browserctl.exe` with no
   `iexplore.exe`/`no-sandbox`/`ignore-certificate`; desktop/Start/Quick-Launch
   shortcuts; Start-menu default = Supermium; `pwrp_k32_sm.dll` watch-proxy layout;
   `URLBlocklist=*`; IE not running; NT 5.1), then a genuine guest-initiated
   shutdown (`{"guest":true}`, `normal_shutdown_frozen`, disk `52842eb7…`).

This image **is** the Milestone-7A offline deliverable, carried under its honest
`XP25-Browser-Experimental.qcow2` name rather than an `XP25-Supermium-Offline.qcow2`
styled as accepted: per the milestone, because the intermittent `0x842214` CHECK is
still reproducible (it fired 0 times in this stability loop and cold boot, but the
GPU A/B shows it can, and it reproduces on stock SP3), the image keeps the
**experimental** designation and must not be described as Internet-safe or accepted.

Reproduction (exact commands used this run):

```
python3 vm/browser_lab.py --base <mp-kernel-base>/disk.qcow2 --sha256 582d551d… \
  --media <prepared-150-05>/browser.iso --suite <prepared-150-05>/install-suite.cmd \
  --name offline-install-01 --mode up --memory 2048 --run-root <runs>
python3 vm/browser_wait_shutdown.py --run <runs>/offline-install-01 --marker XP25_IMAGE_INSTALL_DONE
python3 vm/package_browser_image.py --run <runs>/offline-install-01 \
  --prepared <prepared-150-05> --output <offline-image-01>   # -> XP25-Browser-Experimental.qcow2 + SHA-256
python3 vm/browser_lab.py --base <offline-image-01>/XP25-Browser-Experimental.qcow2 --sha256 6cad84c6… \
  --media <diagnostic.iso> --suite <coldboot-verify.cmd> --name offline-coldboot-01 --mode up --run-root <runs>
python3 vm/browser_wait_shutdown.py --run <runs>/offline-coldboot-01 --marker XP25_COLDBOOT_DONE
```

**Rollback / previous image:** every base used here was a read-only frozen image
driven through a throwaway overlay, so the previous engineering images and the live
`XP25-AI` VM are byte-unchanged and remain the rollback target as-is; the in-guest
`install.cmd`/`rollback.cmd` round-trip (all registry scopes + shortcuts) was
verified in the prior milestone (`browser-modernization.md`) and was not re-run this
session.

## Acceptance status

Milestone 7A is **not** marked accepted — it retains the **experimental**
designation because the intermittent, sometimes-fatal `0x842214` CHECK is still
reproducible (no GPU config avoids it). All of the milestone's executed tests now
pass:

- GPU `0x842214` investigation complete and decided (`--disable-gpu` kept).
- Single-vCPU 20-cycle stability **PASS** (`fstab-up-01`).
- **Two-vCPU 20-cycle stability PASS** (`fstab-mp-04`, 2026-10-28 — 20/20 clean
  cycles, 0 crashes, 0 `0x842214`, 15/15 shell checks, clean guest shutdown).
- UP+MP full functional regression **PASS** (prior, `matrix-150-02`); TCG practical
  functional **PASS**.
- Offline image **produced and cold-boot verified** (`XP25-Browser-Experimental.qcow2`,
  `6cad84c6…`, standalone, 292 files verified; cold boot 15/15 shell cases, clean
  shutdown).

The only outstanding item is the experimental blocker itself — the intermittent
`0x842214` CHECK — which keeps the image experimental and not Internet-safe. Out of
scope (Milestone 7B+): full renderer sandbox, Internet browsing, Trident/Help
removal.
