# Fresh native Winlogon runtime verification

The [later policy/session continuation](winlogon-policy-session-contract.md)
records the current fresh build, real kernel key-protection initialization,
separate native session tests and new limited shutdown/restart results. This
document preserves the evidence for its earlier input; it does not describe
the current policy adapter or current executable hash.

2026-10-24, branch `xp25-nt`, input commit `68f098042`.
**The primary Explorer/Luna objective did not pass.** The exact input failed
native compilation. A corrected, freshly built executable was then booted and
exercised in a new overlay of the latest verified XP25 engineering image.
Authentication and profile/environment initialization pass; shell admission is
blocked by missing licensing orchestration. No new engineering image is made.

## Exact input built first

`W=.work/winlogon-runtime-20261024` and `L=.work/boot-debug-20261022` retain all
private build media, binaries, hashes, command logs and guest evidence.
`W/start.json` records the input commit and all component source hashes.
`W/build-media-01` contains the exact supplied source, including `session.c`
SHA-256 `d0d46be41a8a408d81183ec030120c69ab6fb9a3b402395d4f64c83037a62c89`.
The existing native driver was executed in `L/winlogon-runtime-build-01`, a new
NIC-free overlay of the frozen native Windows XP build VM. Wine was not used.

The actual compiler reports:

* `session.c(194)`: C2065, undefined `WlSessionActive`.
* `bootkey.c(146)`: C2220, warning treated as error.
* `bootkey.c(47)`: C4505, unused `read_stored_key`.

The state machine defines `WlShellReady`, not `WlSessionActive`. The new zero-key
success branch had removed the real stored-key call and made its function
unused. Native build exit is **1**, with **not linking** in the compiler log.
No executable hash or runtime success is attributed to this failed build.
The guest copies of `session.c` and `bootkey.c` hash-match the original input;
`W/exact-build-result.json` and `W/exact-build-evidence` retain that proof.

## Corrections and fresh executable

The real stored SYSKEY request validation/key retrieval was restored. SYSKEY
is LSASS startup authentication, separate from Windows product activation.
No zero-key or forced-success executable was installed in a test guest.
The proposed shell path was retained with these corrections:

* Use `WlShellReady` only after an actual Explorer window, image path, primary
  token, authentication LUID, logon SID and session match have been checked.
* Keep the station locked on the secure desktop and apply the existing user
  desktop/station security before asking GINA to launch processes.
* Give GINA a separate virtual allocation for its environment. The host retains
  its own UserEnv block; this prevents two owners releasing the same block.
* Treat shell, desktop and state-transition failures as failures. Potentially
  started user processes or partially assigned ACLs prevent ordinary pre-shell
  rollback; the current critical-stop path retains the session for diagnosis.

The [GINA handoff contract](https://learn.microsoft.com/en-us/windows/win32/api/winwlx/nf-winwlx-wlxactivateusershell)
requires a copied environment and a locked Winlogon desktop before activation.
The shell-window check runs on a separate thread attached to Default; the
Winlogon UI thread keeps its secure desktop. This code **compiled but was not
executed past admission**. It does not establish functional shell startup,
post-shell cleanup, full notification semantics or complete lifecycle behavior.

Product-activation admission remains explicitly unresolved in
`security.c:wl_session_policy`. It returns `ERROR_CALL_NOT_IMPLEMENTED` before
the GINA callback. This is an implementation gap, **not** a failed licence-server
response or proof about the guest's activation state. The original Winlogon
imports `NtLockProductActivationKeys`; the supplied tree lacks its Winlogon
orchestration and the private COM licensing headers. The repeat investigation
and exact original-host PE imports are retained. No activation records,
authentication returns, protection checks or exception results were patched.
[Known contract gaps](winlogon-activation-investigation.md)

`W/build-media-02` was compiled in the fresh native Windows overlay
`L/winlogon-runtime-build-02`. All eleven source/resource files compile under
`/W4 /WX`; one executable links and binplaces, native exit **0**. Both build
hosts shut down normally; that is not a replacement guest shutdown result.

| Fresh corrected binary property | Recorded value |
| --- | --- |
| SHA-256 | `d0b9c70d4e3937e575be21bb0d55b4267cec7719d5fba083c556b76f817ea815` |
| Architecture / subsystem / image version | i386 PE32 / GUI / 5.1 |
| Bytes / PE checksum | 31,232 / `0xb965`, independently recomputed |
| Direct imports against the actual engineering guest DLLs | All resolved |
| Current source / native build copy / build-media binding | Match |

The matching native PDB and disassembly identify `wl_session_start`,
`wl_session_policy`, the guarded shell callback/transition code and the new
shell-token checker in this executable. No previously compiled Winlogon was
used as the replacement. Static PE checks do not establish desktop acceptance.

## Verified engineering parent and one-file integration

The parent is the latest standalone
`.work/native-shell-userenv-20261024/engineering-image-02/XP25-Components-Engineering.qcow2`,
SHA-256 `39112bbd46f89308180d651a94826808dee3a6acdcc18309b9af7c6d90340296`.
Its whole-file hash and independent cold-boot proof were checked. Offline
readback verifies the manifest's native Explorer, UserEnv, MSGINA, SCM, SMSS,
Regsvc and other retained components. The installed kernel and HAL exactly match
the compiled NT 5.1 UP artifacts. The first verification script used an absent
HAL output path; the corrected check verifies actual `apic/.../halaacpi.dll`
bytes. Both tool logs are retained.

`L/winlogon-runtime-native-kvm-01` is a fresh disposable overlay of that parent.
Before boot, the only explicit guest-file write was
`/WINDOWS/system32/winlogon.exe`. All inspected critical component hashes are
unchanged around that write, and readback of the installed Winlogon exactly
matches the fresh binary. No helpers, startup scripts or guest media were
installed. The original Winlogon is retained at
`L/winlogon-runtime-native-kvm-01/recovery-winlogon.exe`, SHA-256
`7cd68891d5f65be3f045b1c4314d4cfba030bc96ece71d240ad1a1404f1325ea`.

The configuration is single-vCPU KVM, qemu32, i440fx 8.2, 512 MiB, IDE and
standard VGA, with the existing isolated RTL8139 host-lab wrapper. The actual
QEMU command, network-isolation evidence, staging commands, before/after
component hashes and recovery hash are retained in the experiment directory.
No generic SP3 image or recovery image was substituted for the engineering
checkpoint. The frozen parent and user VM disks were never attached writable.

## Actual authentication, profile and failure evidence

| Requested observation | Fresh replacement guest result |
| --- | --- |
| Native Winlogon bootstrap, genuine SYSKEY/LSASS startup, MSGINA login UI | Observed |
| Incorrect existing-account credentials | Original GINA error dialog; actual `LsaLogonUser` `0xc000006d`, substatus 0, Interactive=2 |
| Correct existing XP25 test-account credentials | Actual LSA status/substatus 0/0, Interactive=2 |
| Token, profile SID hive, user environment | Validated by actual native APIs and logged |
| GINA shell callback returns TRUE | Not reached; admission returns error 120 |
| Explorer token ownership, Default input desktop, taskbar/Start/icons/Luna | Not reached |
| Functional desktop, applications, file/registry/network/service regression | Not run under this replacement |
| Normal replacement logoff, restart and shutdown | Not reached |
| Two-vCPU KVM and TCG matrix for this revision | Not run; single-vCPU desktop prerequisite failed |

Read-only hardware breakpoints captured two incorrect/correct authentication
pairs, without changing guest memory, return values or instruction bytes.
Correct logons have distinct actual LSA authentication LUIDs, `0x0000bfcd` and
`0x0000cefb`, in the same fresh Winlogon PID **480**. Primary-token type **1**,
session **0**, and the actual token SID are recorded privately in the serial
and Winlogon logs. The SID hive is checked against that token. No passwords,
startup keys or credential buffers are dumped.

At admission, live readback shows phase StartingShell, owned token/profile,
non-null environment, no owned shell and the new Winlogon checksum `0xb965`.
The matching-PDB-resolved call stack is:

```text
wl_session_policy                 01003f3d
wl_session_start + 0x24            01005cf8
wl_attention + 0x1c7               01005079
notify_window + 0x84               0100305e
USER32 dispatch/callback frames
WinMain + 0xd8                    010034f3
```

`profile-policy-entry.json`, `repeat-profile-policy-entry.json`,
`authentication-api-results.json`, `repeat-authentication-api-results.json`
and `resolved-policy-stack.json` retain raw and resolved evidence. Initial
nearest-public-symbol labels are superseded by the matching PDB's actual
procedure ranges. The GINA-shell entry breakpoint was never reached in either
capture. After continuing, actual error 120 is displayed on Winlogon, the
profile/environment are released, and the token is closed. Ctrl+Alt+Delete
interrupts the next login dialog and permits reentry. Two real initialization
and cleanup cycles pass, including password rejection after rollback. This is
**initialization retry**, not normal desktop logoff/relogin.

A final live capture verifies signed-out state, null token/profile/environment,
null GINA-result/MPR pointers and cleared ownership flags. Kernel/process
inspection confirms the source kernel, one Winlogon PID, the fresh Winlogon
checksum, and no `userinit.exe` or `explorer.exe`. Actual screenshots show the
GINA login, credential rejection and error-120 rollback; none is called an
Explorer/Luna desktop. All 38 focused host checks also pass, without implying
that the blocked shell code ran.

## Preservation and remaining work

The test guest is stopped through host QMP and recorded as
`normal_shutdown=false`; a QCOW2 consistency check is not a Windows shutdown
or filesystem regression. Serial/on-disk log and installed/recovery binary
hashes are retained for offline verification. All 277,863 `Source/` files match
the original 6,322,952,743-byte inventory, manifest SHA-256
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
Prior engineering/reference image hashes and all six user VM definitions are
preserved. No source, binary, inventory or image is uploaded, pushed or deployed.

An established licensing-preserving orchestration contract is still needed to
admit a shell. GPO/volatile-environment persistence and provider scripts also
remain incomplete. After admission exists, the guarded GINA handoff, shell
ownership checks, desktop transition, post-shell failure handling and full
regression/lifecycle matrix must actually run. No activation result is invented,
no incomplete boot is marked accepted, and no standalone XP25 image is generated.
