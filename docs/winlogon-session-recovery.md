# Winlogon session environment and initialization recovery

2026-10-24, branch `xp25-nt`, continued from `9626fa76b`.
**Milestone 5 is incomplete. No authenticated Explorer/Luna desktop or new
engineering image is accepted for the independent Winlogon.**

## Changes to the existing implementation

`session.c` continues to use the original GINA/LSA token and existing UserEnv
profile implementation. It now validates GINA V2's separately allocated UTF-16
environment before merging it into the private user environment. It rejects
malformed entries and duplicate names, uses NT's Unicode name comparison and
expands values against the user's environment, including earlier GINA entries.
It then checks USERNAME, USERDOMAIN, USERPROFILE and the actual console-session
identity. Winlogon's SYSTEM environment is never replaced. The profile-ready
state now follows successful environment preparation.
The [GINA V2 contract](https://learn.microsoft.com/en-us/windows/win32/api/winwlx/ns-winwlx-wlx_profile_v2_0)
specifies the allocation and environment syntax. This is an environment-block
merge; persistent HKCU volatile-environment/GPO integration remains unfinished.

Initialization failure now keeps the workstation on the secure desktop,
waits for outstanding user-token notification jobs, calls GINA's logoff cleanup,
frees its returned allocations, destroys the host environment, unloads the
profile, and finally closes the token. Only successful cleanup clears identity
and returns the state machine to signed-out. The user sees the original error
number and can authenticate again. Failed cleanup retains ownership and enters
the existing fatal recovery path. This is recovery before shell admission,
not a completed desktop logoff.

Startup notification workers have machine lifetime. In particular, the supplied
CSC `WinlogonStartupEvent` explicitly calls a routine that remains active until
shutdown (`base/fs/rdr2/csc/usermode/reint/ntstuff.c`, lines 171–244). Joining that
worker during user rollback caused the first experimental build to stall and
then time out. User cleanup now joins only jobs with a duplicated user token;
the tokenless workers and their DLL references remain owned. The general
notification join also services synchronous sent GUI messages without
removing/dispatching posted SAS or input messages. Actual user-token callback
joining, timeout/revert failures and hostile reentry still need dedicated guest
fault tests; this continuation exercises the machine-worker separation.

Two incoming uncommitted forced-success edits were saved exactly under
`W/incoming/` and `W/incoming.diff`, then restored to the committed stored-key
validation and activation-policy error before building. SYSKEY is an LSASS
startup authentication mechanism, distinct from product activation. No zero-key
or unconditional shell-admission variant was built by this continuation.

## Native build and reproducibility

`W=.work/winlogon-lifecycle-20261024` and
`L=.work/boot-debug-20261022` hold private artifacts. `W/commands.jsonl` records
executed build/test commands and the corresponding logs; each VM retains its
QMP journal, input hashes, QEMU command and disk check.

The final native build uses `W/build-media-04`, the existing frozen
`L/userenv-rebuild-01/disk.qcow2`, and `L/winlogon-lifecycle-build-02`.
The native NT build driver compiles all eleven source/resource files with
`/W4 /WX`, links and binplaces one i386 executable successfully. The build host
shuts down normally. This is build-host evidence, not replacement-OS shutdown.
The PE is 28,672 bytes, GUI subsystem, image version 5.1, checksum `0x112e4`,
SHA-256 `2fc1ea1a801362db4e608becc52531ddbd7874ed530ea293e6b7fe9e9e1dbf55`.
All sixteen component files match the frozen build-media manifest.

The build-02 host initially attached media02; QMP CD changes adopted media03
and then final media04. Earlier UI submission produced no build markers while
Explorer opened the CD. The final `cmd /k D:\build.cmd
C:\xpout\winlogon-lifecycle-02` submission produced the recorded build exit 0.
`adopted-build-media.json` and the QMP journal preserve the media changes.
No successful build is claimed for media02 or media03.

Use `W/launch-matrix-02.py` to reproduce the disposable replacement matrix.
It uses the previously frozen fixture parent, SHA-256
`f1ed3d30cbb7269d0e6c43990359223db794eb67d9f277d614fd8984943e1e3c`,
and existing native component/test paths. The parent retains original Winlogon
and the local test account; no existing account password is changed.
`W/exercise-ui-02.py` and the journals preserve actual keyboard input. These
private scripts are experiment recipes, not an accepted desktop automation suite.

## Recorded coverage and limitations

The final experiments are `winlogon-lifecycle-native-kvm-02`,
`winlogon-lifecycle-native-kvm-mp-02` and
`winlogon-lifecycle-native-tcg-02`. All three perform two real authentication,
SID-hive verification, GINA-environment merge, profile/environment preparation,
error-120 rejection and successful cleanup cycles. Ctrl+Alt+Delete interrupts
the next authentication dialog and permits reentry. Live read-only captures
verify matching UP/MP kernel checksums and the compiled Winlogon checksum,
no Explorer process, cleared ownership flags and null token/profile/environment,
GINA-profile and MPR pointers after rollback. TCG's resource capture is in a
subsequent authentication attempt with no acquired user resources. Bad
passwords are visibly rejected after rollback in all three configurations; the
reviewed captures are `negative-after-retry.png` for KVM/MP and
`final-negative.png` for TCG. Earlier TCG captures were taken before its delayed
error dialog appeared and are retained without counting them as rejection
evidence. Final serial and offline on-disk host logs match byte for byte.
The installed Winlogon and original recovery bytes match their expected hashes;
all direct PE imports resolve against the extracted guest DLLs. Full component
and dependency hashes, six checked preparation/cleanup cycles and explicit
`primary_milestone_accepted=false` are recorded in `W/component-manifest.json`.

All 38 host checks pass. The environment helper now has 24 cases, including
truncated/malformed iteration, empty values, drive entries and Unicode values;
its AddressSanitizer/UndefinedBehaviorSanitizer run passes. The state-machine
suite still executes 320,991 assertions. These checks do not establish an
OS desktop, profile-policy compatibility or hostile-user security equivalence.
The first parser test iteration had an incorrect truncated-buffer expectation;
its failed log and correction are retained.

The first native matrix (`*-01`) is rejected: its all-worker join cannot
complete while CSC is running. Its logs, screenshots, read-only thread/stack
captures and frozen disks remain available. The initial stack capture used
an incorrect trap-frame offset; the corrected capture uses the supplied x86
`ThTrapFrame=0x134`. Some kernel stacks had been paged out; the diagnostic then
read only user-stack code pointers through the process's existing page tables.
No exception return, credential, executable code or authentication result was
changed. Attempts to extract absent optional `.err`, `.wrn` and `.map` files,
and the MSF7 parser's rejection of this MSF2 PDB, are retained as tool limitations.

**The concrete desktop blocker remains
`activation_policy_contract_unresolved`, error 120.** The original Winlogon
orchestration source and the licensing COM headers are absent from the supplied
tree. The repeat search and the known interface gaps are recorded in
[the activation investigation](winlogon-activation-investigation.md).
A verified licensing-preserving orchestration contract is required before
calling [WlxActivateUserShell](https://learn.microsoft.com/en-us/windows/win32/api/winwlx/nf-winwlx-wlxactivateusershell).
The callback's environment handoff, network-provider scripts, userinit/Explorer
launch and ownership confirmation, desktop switch, shell recovery,
lock/unlock, full logoff/relogin, shutdown/restart, critical-process recovery,
secure-desktop hostile-user restrictions and application/file/registry/network/
service regressions under the replacement remain unfinished or untested.
Profile-load/unload failure injection also remains untested.

No standalone image is generated. Experimental guests are stopped through
host QMP and marked `normal_shutdown=false`; none is counted as an accepted
guest shutdown or a completed login. The previous engineering images, original
recovery executable, reference tree and all six user VM configurations remain
preserved.
All 277,863 reference files (6,322,952,743 bytes) match the original source
inventory, manifest SHA-256
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
Generated artifacts and evidence remain under `.work/`; no source or media is
uploaded, pushed or deployed.
