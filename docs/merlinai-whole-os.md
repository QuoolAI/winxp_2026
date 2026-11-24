# MerlinAI repairs XP25 itself (Milestone 9, from 2026-11-24)

Until 2026-11-23 the MerlinAI Builder rebuilt only MerlinAI's own six programs. The Milestone 9 spec asks
for more: MerlinAI diagnoses XP25 problems, changes XP25's source, rebuilds the affected components and
builds a personalized replacement image. This record covers steps 1 and 2 of closing that gap:
- the other XP25 components;
- the Microsoft components XP25 builds from the reference tree, starting with the kernel.

The first real case is a defect on the XP25-Winlogon-Fix VM: the Filter Manager (FltMgr) does not load.
Third-party software (step 3) is not part of this record.

Evidence `.work/merlin-os-20261124/` (`O`) and native runs under `.work/boot-debug-20261022/merlin-os-*`
and `merlin-j-*`. `Source/` is read, never written.

## The FltMgr defect

On every boot the VM's System log records Service Control Manager event 7026: *"The following boot-start
or system-start driver(s) failed to load: FltMgr"*. MerlinAI had queued it as problem
`P-56c9d7d8edcaae64` (28 occurrences since 2026-10-23).

* `fltmgr.sys` is the Service Pack 3 driver (5.1.2600.5512). It imports 172 kernel functions, and one of
  them is missing from XP25's source-built kernel: `RtlAddAccessAllowedAceEx`. Microsoft's own SP3 kernel,
  which is installed but unused, exports it.
* The 5.1.2600.1106 reference source implements it in `base/ntos/rtl/acledit.c:1689`, and that file is
  compiled into both kernel runtimes (`rtl/up`, `rtl/mp`). The kernel's export list
  `base/ntos/init/ntoskrnl.src` simply does not list it. `public/sdk/inc/ntrtl.h` declares it
  `NTSYSAPI NTSTATUS NTAPI`, the same API.
* This is the same class of defect as the Windows Firewall driver in Milestone 8, which imported
  `KeFlushQueuedDpcs`.

A survey of all 172 drivers in the image against the installed kernel and HAL found four more with
missing kernel imports:

| Driver | Missing from XP25's kernel | Status |
| --- | --- | --- |
| `fltmgr.sys` | `RtlAddAccessAllowedAceEx` | **repaired here** |
| `http.sys` (HTTP service) | `ExfAcquirePushLockExclusive`, `ExfAcquirePushLockShared`, `ExfReleasePushLock`, `RtlAddAccessAllowedAceEx` | not repaired: the push-lock routines are FASTCALL, and the SP3 driver's inline fast paths must match SP1's push-lock layout. That needs an argued compatibility check, which the offline rule refuses to make |
| `srv.sys` (Server service; Computer Browser depends on it) | `RtlIpv4AddressToStringExW` | not repaired: the reference source does not implement it |
| `dumpdrv.sys` | `IoInitializeCrashDump` | not examined (crash-dump helper) |
| `ntfs.sys` | `SeAuditingFileEventsWithContext`, `SeAuditingHardLinkEventsWithContext` | no defect: XP25 boots its own source-built `xp25ntfs.sys` through the Ntfs service's ImagePath; the SP3 file is unused |

## Provenance: rebuilding what is installed, not just "the source"

A rebuilt component may replace an installed one only if the job's source is what the installed file was
built from. Otherwise the update would silently carry unrelated differences. This mattered at once:

* The builder's build VM holds a prebuilt kernel (`f8700fd2…`, linked 2026-10-22) whose `.text`, PAGE and
  INIT sections differ from the installed kernel's (`b9531947…`, relinked 2026-11-11 in Milestone 8). A
  naive "take the build VM's kernel" would have shipped different code.
* A **control relink** with XP25's current export list (`O/merlin-os-kxctl-02`) reproduces both installed
  kernels exactly: every section of UP `b9531947…` and MP `42662074…` is identical once the link time stamps
  are masked (PE header, export directory, debug directory and CodeView record).
* For the other XP25 components, control builds from today's source compared with image-04's installed files:

| Recipe | Control build vs installed (image-04) |
| --- | --- |
| winlogon | `winlogon.exe` `020eaf40…` reproduced |
| security | `XP25Sec.exe`, `XP25Audit.exe` reproduced |
| merlin | 5 of 6 reproduced; `MerlinCrash.exe` differs as expected (today's source is build 12; the image has build 10, which a job builds from the baseline's own commit) |
| ai | **not reproduced**: ClippyAI, RoverAI, RoverAIBand, xp25agent and XP25Broker were built from older source. The builder refuses to replace them on this baseline |

So every recipe except MerlinAI now has a **control build** in every job: the job's unchanged baseline
source is built first and must reproduce the installed binary. The candidate is then compared with the
control build. For the kernel both builds run in one build-VM session. MerlinAI keeps relying on the
baseline's recorded commit, as before.

## What the builder does now

* **Recipes** (`components/merlin/builder/merlin_builder/components.json`). Every rebuildable binary names
  its recipe, source, build output and installed path:

  | Recipe | Builds | Driver |
  | --- | --- | --- |
  | `merlin` | MerlinAI's six programs | `build/native-merlin-build.cmd` |
  | `winlogon` | the XP25 Winlogon | `build/native-winlogon-build.cmd` |
  | `ai` | ClippyAI, RoverAI, RoverAIBand, xp25agent, XP25Broker | `build/native-ai-build.cmd` |
  | `security` | XP25Sec, XP25Audit | `build/native-security-build.cmd` |
  | `nt-kernel` | `xp25krnl.exe` (UP and MP) from `Source/XPSP1/NT/base/ntos` | `build/native-nt-recipe-build.cmd` |

  The kernel entry lists its known installed builds (UP `b9531947…`, MP `42662074…`).
  `build/prepare_recipe.py` makes the media for any recipe from a job workspace, and
  `vm/native_recipe_build.py` builds them in a disposable build VM and collects the results.
* **Microsoft source in the builder.** `builder_vm.py reference-source` copies `Source/XPSP1/NT` into the
  builder VM as a squashfs image (xz) mounted at `/srv/merlin/reference/nt`. It is read-only by
  construction and checked by a digest of every file, taken on the mounted image, before anything already
  installed is replaced (277,863 files, `668b2929…2127`). An
  investigation sees each Microsoft file as its **effective source**: the reference plus XP25's own change.
  For `ntoskrnl.src` that change is the Milestone 8 export list, applied by the same function
  `build/prepare_kernel_exports.py` uses. Edits go to the job's overlay, and only inside directories a
  recipe rebuilds (today `base/ntos`). A host test checks that the reference stays unchanged.
* **Investigation tools.** `installed_binary` reads a binary from the user's own system image (version,
  hash, provenance, and every import the installed system does not export). `merlin_builder/pe.py` and
  `sysimage.py` provide it, resolving `ntoskrnl.exe` and `hal.dll` to the kernel and HAL that `boot.ini`
  starts. The model's prompt now describes XP25's three kinds of code and tells it how SP3 binaries fail on
  an SP1-source core. When no model is configured, the offline rules export a kernel function only when all
  of these hold:
  - a driver that does not load imports it;
  - Microsoft's own later kernel exports it;
  - the reference kernel defines it;
  - a public header declares it `NTKERNELAPI`/`NTSYSAPI`, not FASTCALL.
* **Provenance step.** The control build must reproduce the installed binary, and for the kernel also the
  multiprocessor kernel the two-CPU tests boot. The candidate may not drop exports. Every import of a
  rebuilt binary must resolve on the installed system. The job records the result per binary under
  `provenance`.
* **Tests.** A driver that did not load gets a check `{"driver": NAME}`: the job test queries the service
  (`sc query`) before and after. The name comes from the report, so it is validated, and it must be an
  installed driver. A rebuilt kernel is tested under two CPUs as its own multiprocessor build. Each
  problem is judged by its own checks.

## Results for FltMgr

* Kernel recipe build, from the offline rule's change (`merlin-os-ntk-01`, accepted). The control builds
  reproduce the installed UP and MP kernels exactly. The candidates (UP `68102af6…`, MP `d312d887…`) are
  identical to them in every section except the export table, with exactly one export added,
  `RtlAddAccessAllowedAceEx`, and none removed.
* Direct boot check on overlays of image-04 (`O/quick/runs`): before, `sc query FltMgr` shows
  `STATE : 1 STOPPED`; with the candidate kernel, `STATE : 4 RUNNING`. Both boots pass boot, logon, desktop,
  checks, MerlinAI status and guest-requested turn-off (6/6). HTTP stays stopped, as expected.
* The full pipeline on the host (`vm/merlin_builder_local.py`, baseline image-04, offline investigator):

  job `J-20261124-081009-993889` (`O/local-01/data/jobs/`) is **ready, `fixed_verified`**, in 529 s. Its steps:
  - **Investigation.** The change is one line, `+    RtlAddAccessAllowedAceEx`, after `RtlAddAccessAllowedAce`.
  - **Kernel build.** It took 3 minutes.
  - **Provenance.**
    - The control build reproduces the installed kernel `b9531947…` and the MP test kernel.
    - The candidate is identical to the control build in code.
    - The only export added is `RtlAddAccessAllowedAceEx`, and every import resolves on the installed system.
  - **Candidate.** It replaces two files: `xp25krnl.exe` (`5d7772f0…`) and the revision file, which becomes
    `XP25-Winlogon-Fix-MerlinAI-1+J-20261124-081009-993889`.
  - **Tests.**
    - Before: `XP25_JOBTEST_DRIVER_FLTMGR=not_running` (reproduced).
    - After: `running` under KVM UP, two-vCPU KVM (the candidate's own MP kernel) and TCG.
    - All 18 regression gates pass: boot, logon, desktop, checks, MerlinAI status and normal turn-off, in each
      mode.

  The two earlier jobs on the same problem failed and are kept (see the defect table).

* MerlinAI-Builder VM, from the XP25-Winlogon-Fix VM's own *Build an Update*:

  The MerlinAI-Builder VM runs tools `950f07903` (snapshot `aeae4d75…`). The default baseline snapshot
  reproduced as `c88f545de`; the reference image, five baselines and gpt-4.1 are configured.
  The request came from the XP25-Winlogon-Fix VM itself: MerlinAI → Problem Queue → tick *Boot or system
  drivers failed to load (Drivers: ??FltMgr)* → Build an Update. Evidence: screenshots `00`–`09` and
  `builder-job-J-20261124-103813-56bc78.json` in `xp25-merlin/.work/merlin-vm-20261122/deploy-02/`.
  - Job `J-20261124-103813-56bc78`, baseline `xp25wf4`, is **ready, `fixed_verified`**, 16 minutes after
    the request.
  - **gpt-4.1 found the cause with the new tools.**
    - `installed_binary fltmgr.sys` showed the unresolved import.
    - It searched `base/ntos/rtl`, read `acledit.c` and the `ntrtl.h` declaration, then read
      `ntoskrnl.src` and added the export. It placed it at the top of the list; the linker assigns ordinals
      alphabetically, so placement does not matter.
  - **Provenance.** As in the local job: the control build reproduces the installed kernel and the MP test
    kernel, the candidate is identical in code, and one export is added.
  - **Ordinals.** The new export takes ordinal 926, and 540 later exports move up by one, exactly as in
    Milestone 8 when `KeFlushQueuedDpcs` was added. None of the 1,695 executables in the image imports the
    kernel by ordinal. The builder now checks this itself (`94c2459cb`).
  - **Nested tests in the builder.** FltMgr was not running before, and runs under KVM UP, two-vCPU KVM and
    TCG; 18/18 regression gates pass.
  - **On the VM.** Previous Builds shows the job as ready with the candidate available. Review Build shows
    the investigator, the conclusion, the change, the rebuilt `xp25krnl.exe` and the tests; it does not show
    the new provenance record yet (the native client predates it).
  - **Not applied.** Applying replaces your kernel and is your decision. The VM was turned off normally
    afterwards (disk `2a2b0bb2…`).
  - **Applied later that day by the user** in the VM (MerlinAI → Previous Builds → Review Build → Apply Update).
    The agent wrote both files into a new layer (`apply_written`). The VM reported revision
    `…+J-20261124-103813-56bc78` 15 s after start (`apply_healthy`, 17:14:18Z). See
    [mea-xp25-desktops.md](mea-xp25-desktops.md).

## Defects found on the way (failures kept)

| Found by | Defect | Fix |
| --- | --- | --- |
| first control relink attempt | the lab tool boots only frozen images under the checkout's `.work/` | a frozen overlay of the builder's build-VM chain (`O/reference/builder-buildvm.qcow2`) |
| kernel comparison | the export directory carries the link time stamp; the first comparison reported `.edata` as changed | the export time stamp is masked like the other link stamps |
| control builds of the XP25 recipes | `--guest-modules` defaulted to a path that exists only in the `xp25-merlin` worktree, so every import was "unavailable" | the driver refuses a guest-modules directory without `user32.dll`; imports are checked with `pe.py`; a DLL the copy lacks is recorded as unchecked, and the builder checks every import against the baseline image |
| AI control build | the installed AI binaries were built from older source | control builds in every job for every recipe except MerlinAI |
| copying the reference tree into the builder | 6.7 GB of loose files grew the builder's data disk; with the day's runs, the host disk reached 98% (6.2 GB free) and the next local job waited for space | the tree is a compressed read-only squashfs image; `--reuse-installed` converted the installed copy in place (digest checked on the image), and `fstrim` returned the space through the disk's `discard=unmap` |
| second local job `J-20261124-073141-cb7b0f` (failed, kept) | the kernel build succeeded, but `xp_lab shutdown` waited only 60 s for the build VM to power off while the host was busy with the reference copy (load average ~14; the screenshot shows "Windows is shutting down…") | `xp_lab.py --shutdown-timeout`; the recipe driver waits up to 600 s |
| first local job `J-20261124-071818-4dbc43` (failed, kept) | `XP25_JOBTEST_DRIVER_FltMgr=…` markers were not captured: the job test keeps only `XP25_[A-Z0-9_]+` markers. The guest logs showed not_running before and running after in all modes | marker names are upper case; a host test runs the extractor over the generated marker |

## Limitations

* NT recipes: only the kernel (`base/ntos`) is wired. The other 22 Microsoft-source components are mapped
  to their source but not rebuilt yet. Binary-only components (`shell32`, `ole32`, `advapi32`, …) cannot be
  rebuilt.
* Kernel *code* changes (not just the export list) take the same path: changed library directories are
  built first, then the kernel is relinked. That path has not been exercised by a job yet.
* HTTP and Server remain broken (see the table above); `dumpdrv.sys` was not examined.
* The AI components cannot be repaired on the XP25-Winlogon-Fix baseline until it is rebuilt from the
  source its AI binaries came from, or redeployed from current source with a full regression.
* Third-party software failing on XP25 (step 3) is not done: there is no reproduction of a third-party
  program's failure inside the candidate image, and no dump analysis.
* The offline rules are deliberately narrow. Anything else needs the model investigator, whose kernel and
  driver reasoning is only as good as the model's.
* The VM's Review Build does not show the provenance record (control build, exports added); the builder's
  job record has it. Showing it needs a MerlinAI client update.
* The FltMgr update was applied to the XP25-Winlogon-Fix VM by the user on 2026-11-24. Its export is not yet in
  the repository's kernel export list ([development-with-merlinai.md](development-with-merlinai.md)).

## Reproduction

```bash
O=.work/merlin-os-20261124
python3 build/prepare_kernel_exports.py --output $O/kx-control-media           # control relink media (Milestone 8 list)
qemu-img create -f qcow2 -F qcow2 -b <xp25-merlin>/.work/merlin-builder-vm-20261121/vm-01/ro-buildvm/00-disk.qcow2 \
  $O/reference/builder-buildvm.qcow2 && chmod 0444 $O/reference/builder-buildvm.qcow2
python3 build/prepare_recipe.py --recipe nt-kernel --output $O/nt-kernel-media-01 --reference Source/XPSP1/NT \
  --nt-changes $O/fltmgr-change
python3 vm/native_recipe_build.py --media $O/nt-kernel-media-01 --name merlin-os-ntk-01 --base $O/reference/builder-buildvm.qcow2
python3 build/prepare_recipe.py --recipe winlogon --output $O/control-media-winlogon     # likewise ai, security, merlin
python3 vm/native_recipe_build.py --media $O/control-media-winlogon --name merlin-os-ctl-winlogon-01 \
  --base $O/reference/builder-buildvm.qcow2 --guest-modules <guest system32>
python3 vm/merlin_builder_local.py init --dir $O/local-01 --commit 00176467b --baseline-image <image-04> \
  --baseline-sha256 378e9edd71f9fc3435800ca3b0ad856a08f435e3a6b09e66d2dc32fee3e58183 --revision XP25-Winlogon-Fix-MerlinAI-1 \
  --symbols <symbols-native-10> --modes up,mp,tcg --build-vm $O/reference/builder-buildvm.qcow2 \
  --reference <xp25-merlin>/.work/merlin-builder-vm-20261121/reference --nt-reference Source/XPSP1/NT
python3 vm/merlin_builder_local.py submit --dir $O/local-01 --problem-json $O/fltmgr-problem.json
python3 vm/merlin_builder_local.py run --dir $O/local-01
B=<xp25-merlin>/.work/merlin-builder-vm-20261121/vm-01
python3 components/merlin/builder/deploy/builder_vm.py reference-source --dir $B --source Source/XPSP1/NT
```
