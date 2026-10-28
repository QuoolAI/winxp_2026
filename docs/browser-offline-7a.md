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
| Two-vCPU KVM, 20-cycle loop | **NOT TESTED (two attempts, both blocked by host contention)** — attempt 1: host RAM saturated by a ~26 GB non-browser VM; the MP loop was swapped out and did not finish (`fstab-mp-01`, frozen incomplete). Attempt 2 (`fstab-mp-02`, 2026-10-28, byte-identical media `5414e69e…` + suite `4887e522…`): launched when ~24 GB was free, but a ~20.5 GB libvirt `win11-1` guest (not ours) started moments later; the MP guest **halted at early boot and never ran the suite** — QMP `status=shutdown`, ~8 CPU-seconds then frozen, overlay untouched (917504 bytes), serial empty, framebuffer stuck at a 640×480 dark-blue (RGB 0,0,128) boot/BSOD screen (`incomplete-final.ppm`); froze and reaped cleanly, other VMs untouched. Consistent with a contention-induced early-boot/SMP-bringup failure, **not** a browser defect: MP boot + full functional regression previously **passed** in `matrix-150-02`. This dedicated MP 20-cycle stability loop therefore remains not successfully executed. | `X/runs/fstab-mp-01`, `X/runs/fstab-mp-02` |
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

**NOT TESTED / NOT PRODUCED.** Producing the offline image
requires a fresh install boot, packaging, and an independent cold-boot verification
plus final regression — at least two guest boots. The image was not produced across
two windows: first with a ~26 GB non-browser VM leaving ~1 GB free, and again on
2026-10-28 when a ~20.5 GB libvirt `win11-1` guest (not ours) left ~5.7 GB free and
caused the concurrent MP-stability guest to fail early boot (see the stability
table). Launching the install guest under that contention risked OOM-killing another
agent's VM and would likely reproduce the same early-boot failure, so no image was
produced rather than produce an unverified one. The clean install media is staged
and verified (`X/prepared-150-05`: software-rendering, `URLBlocklist=*`, no
remote-debugging bridge, install-suite `ab8f7ddf…`; Supermium 150 R2.01 pin
`d9a06a6c…`); `package_browser_image.py` flattens to a standalone compressed
`XP25-Browser-Experimental.qcow2` (name and manifest carry the **experimental**,
`status=experimental_unaccepted` designation — this *is* the offline deliverable
under its honest experimental name, not `XP25-Supermium-Offline.qcow2` as an accepted
artifact). An offline cold-boot verify suite (13 shell checks against the installed
image, no reinstall, no network) is staged. When host memory allows, the
reproduction is:

```
# fresh install overlay (software rendering), then package + cold-boot verify
python3 build/prepare_browser.py --package <144-or-150 zip> \
  --browserctl <native>/browserctl.exe --launcher <native>/XP25Browser.exe \
  --pwrp-proxy <native>/pwrp_k32.dll --software-rendering --output <prepared>
python3 vm/browser_lab.py --base <AI engineering base> --sha256 <hash> \
  --media <prepared>/browser.iso --suite <prepared>/install-suite.cmd \
  --name offline-install --mode up --run-root <runs>
python3 vm/browser_wait_shutdown.py --run <runs>/offline-install --marker XP25_IMAGE_INSTALL_DONE
python3 vm/package_browser_image.py --run <runs>/offline-install \
  --prepared <prepared> --output <image>          # -> XP25-Supermium-Offline.qcow2 + SHA-256
# then a fresh overlay cold-boot + 13 shell checks + shutdown to verify independence
```

The produced image must carry the **experimental** designation (0x842214 blocker
unresolved) and must not be described as Internet-safe. Rollback (`install.cmd` /
`rollback.cmd`, all registry scopes + shortcuts) round-tripped in the prior
milestone (`browser-modernization.md`). Previous engineering images and the live
`XP25-AI` VM are untouched.

## Acceptance status

Milestone 7A is **not** marked accepted. Executed tests pass (GPU investigation
complete and decided; single-vCPU 20-cycle stability PASS; prior full KVM
regression and TCG practical functional PASS). Outstanding: the intermittent,
sometimes-fatal `0x842214` CHECK (experimental blocker, no GPU config avoids it);
two-vCPU 20-cycle stability and the accepted offline image (NOT TESTED — blocked by
host memory contention in two separate windows; the 2026-10-28 MP retry reached only
a failed early boot under a ~20.5 GB non-browser VM, reaped and frozen). Both remain
reproducible from staged, verified inputs the moment the host frees. Out of scope
(Milestone 7B+): full renderer sandbox, Internet browsing, Trident/Help removal.
