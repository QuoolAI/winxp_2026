# MerlinAI crash-dialog readiness, 2026-11-22/23

The two-vCPU 9A test of native build 10 sent keyboard input after
`XP25_MERLIN_CRASH_CAPTURED ... interactive=1`. That record precedes
`end_target()`, whose debugger-event drain can take ten seconds. The harness
waited six seconds before typing. The retained MP run
`xp25-merlin/.work/merlin-20261121/runs/merlin-9a-mp-04` passed 21/24 and
recorded `dont_send`; capture was not evidence that the dialog could accept
input. UP and TCG passed 24/24 in their separate build-10 runs.

`MerlinCrash` now emits `XP25_MERLIN_CRASH_DIALOG_READY` after initializing the
report controls and requesting the foreground. The harness waits for that
record within the interactive-crash phase before sending its existing dialog
keys. Its existing settling interval remains. No consent or reporting action
is automated in an installed system: this is the disposable test harness.

A focused host test feeds capture without readiness, verifies that no keys are
sent, then feeds readiness and verifies Send is attempted once. All 26 MerlinAI
host tests pass, including the sanitizer core and builder/deployment tests.
ResourceWarnings about unclosed test-server sockets remain in the log; the run
has no test failures.

## Evidence and native build

New evidence is in the main checkout, not the retired worktrees:

* `W = .work/merlin-dialog-ready-20261122/`: prepared media manifest, host logs,
  `commands.json`, runtime staging, and disposable MP run;
* `N = .work/boot-debug-20261022/merlin-dialog-native-11/`: build input hashes,
  command journal, COM1 build log, shutdown event, frozen disk and collection.

`W/evidence-index.json` hashes the command record, host logs, build collection,
runtime inputs, COM1 log, result, checkpoint and shutdown event.

The native Windows build exits zero and its log has no NMAKE failure marker.
All six outputs exist, all 52 compiled-source records match the media, and
imports are checked against the recorded XP guest modules. The build VM
requested normal shutdown; `qemu-img check` passed during finalization.
This establishes PE compilation and source provenance separately from the
runtime result below.

| Artifact | SHA-256 |
| --- | --- |
| Native media ISO | `08886e70d41147ecc3f247bd391e2478197fe2bae73c17545af7adc811807a0d` |
| Native `MerlinCrash.exe` (32,256 bytes) | `4372909d2cbbcd4416072dc6474e253b0ff293be06a7b957c92bb7b798feb69d` |
| Frozen successful MP overlay | `9181f66ea445fc1fd91cf261d640b79954b3171f4860744bf8c93fc9ad714eb0` |
| MP COM1 log | `70417a64c338e54a49cf12be5d6132c01b2ceb34cf181eff579a6f70b0e5f9cb` |
| MP lab backing image, existing M9 baseline | `a3bde9b2836aad585fe7dc95cc056a7845e7f1940f95e40a0ba381c322d15e08` |

The media manifest identifies parent commit `361a3b6d0` and records the
uncommitted crash-source change; the exact compiled files have individual
hashes. The build base and M9 runtime image are private reflink copies;
existing backing chains remain read-only. Only the original project's native
NT 5.1 x86 toolchain builds the guest components. `Source/` is unchanged.

## Focused runtime result

`W/runs/dialog-ready-mp-01/results.json` passes **24/24** under two-vCPU
KVM, using the original verified MP kernel/HAL on a disposable overlay of the
M9 baseline. The native build-11 crash executable is the hash listed above.
The guest emitted dialog readiness, then `CHOICE=send`, `queued=0` (success),
`transfer=1` and `CRASH_TRANSFER=0`. Offline queue and builder records confirm
consented transmission; no build starts from Send. Control Panel replacement,
UI-requested build and authenticated health reporting also pass. QMP records
`guest=true`, `reason=guest-shutdown`; finalization freezes the overlay and
checks its QCOW2 structure.

Build 11 was tested in this MP configuration only. Build-10 UP/TCG passes
remain historical evidence for build 10. The previous failed MP run is kept;
a single passing focused rerun does not establish long-term stability.

This continuation does not package build 11 into a release image, replace a
registered VM's disk, change the running builder, or submit another model job.
Build-10 image-04's broader recorded compatibility results remain separate:
[image-validation record](merlinai-milestone9.md#model-investigation-and-vm-image-validation-2026-11-2223).
The readiness marker is diagnostic, not a claim of OS or application support.

## Commands

Run from the main checkout. Fresh output names are required. Prior evidence
and toolchain paths remain private local inputs.

```bash
W=.work/merlin-dialog-ready-20261122
P=../xp25-merlin/.work/merlin-20261121
python3 build/prepare_merlin.py --output "$W/native-media-11"
python3 vm/merlin_native_build.py --media "$W/native-media-11" \
  --name merlin-dialog-native-11 --base "$W/reference/buildvm.qcow2" \
  --guest-modules "$P/guest-modules-82/WINDOWS/system32" \
  --toolchain .work/toolchains/mingw-binutils/usr/bin
python3 -m unittest discover -s tests -p 'test_merlin*.py' -v
XP25_MERLIN_WORK="$PWD/$W" python3 "$W/run-mp.py"
git diff --check
```

`run-mp.py` retains the exact launch/wait/results arguments in
`W/commands.json`. It copies the accepted native collection and the existing
lab-only probe, then tests with the hash-checked original MP kernel and HAL.
The probe is never installed as a product component. Build logs, failed earlier
runs and input images are retained; nothing is uploaded, pushed or deployed.
