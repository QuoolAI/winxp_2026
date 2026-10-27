# Native Explorer and UserEnv integration, 2026-10-24

Continuing `cda64291e` on `xp25-nt`, original-source Explorer and UserEnv pass
integration separately and together under one-vCPU KVM, two-vCPU KVM and TCG.
The changes correct demonstrated SP1/SP3 ABI mismatches. Winlogon, exception
handling, authentication policy and licensing code are not patched. This
supersedes the unresolved results in [the previous checkpoint](native-component-extensions.md).
Earlier rejected candidates and the previous engineering image are preserved.

Private evidence is under `.work/native-shell-userenv-20261024/` (`W`), and
guest runs under `.work/boot-debug-20261022/` (`L`). Exact commands, native build
logs, exception bytes, mapped module identities, PDB provenance, QMP journals,
packet captures, retained files and acceptance reports stay local. Nothing is
pushed or uploaded. `Source/` remains the reference, not the build directory.

## Explorer: wrong private SHLWAPI call

`L/explorer-first-exception-03` reproduces the old candidate's startup crash in
a fresh TCG child paused before boot. `vm/capture_exception.py` uses the matching
native kernel map to capture the first access violation, user trap registers,
EBP frames, stack, instructions and mapped module paths/checksums/timestamps.
Earlier GDB/protocol and generated-script failures remain separate evidence.

The fault is **SHLWAPI 0x77f773b6**, `andl $0,(%eax)`, writing through EAX
**0x6891f6fd**, an address in Kernel32 code. Callers are SHLWAPI **0x77f69f04**
and native Explorer **0x01018051**, in `WaitForSCMToInitialize`.
`shell/explorer/initcab.cpp:1125` calls
`CreateAllAccessSecurityAttributes(NULL,NULL,NULL)`: an SP1 three-argument,
stdcall-12 import through **SHLWAPI ordinal 356**. Installed SP3 ordinal 356
is a different six-argument function. Import availability missed this mismatch.

Working installed SP3 Explorer's corresponding event wait calls **SHLWAPI 563
with no arguments**. Disassembly of that exact installed provider establishes
the same security descriptor policy: Everyone `0xe0100000`, SYSTEM and
Administrators `0x10000000`. It returns `SECURITY_ATTRIBUTES*` with plain `ret`.
`build/prepare_shell_compat.py` changes only this call site in a disposable copy,
resolves 563 through a typed `WINAPI` pointer, and fails on an absent provider
or NULL result. Original CreateEvent/OpenEvent handling remains. No permissive
ACL or success stub is substituted.

The generated CD verifies original source bytes with `fc /b` before copying
the patch into `C:\nt`. It reuses `build/native-shell-build.cmd`, original
BrowseUI/Shdocvw specifications and the seven previously established NONAME
decorations. `L/explorer-compat-build-01` compiles 24 Explorer units and links
the executable with all target results zero. Only the two prior reviewed XP25
Start-menu resource labels are then applied; code and VERSIONINFO are preserved.

`W/shell-private-interface-audit.json` matches **131 direct ordinal imports**
across BrowseUI, Shdocvw, Shell32 and SHLWAPI to original `.src` names/aliases
and installed matching public symbols after removing the invalid 356 dependency.
This does not establish every unexercised private COM/vtable/structure contract.
Runtime evidence covers desktop startup, Start menu and real folder navigation.

## UserEnv: four private ordinals corrupt Winlogon's stack

The previously reported **0x0100ced1** NULL write is a **first-chance exception
inside an internal Winlogon SEH trampoline**. A fresh working SP3 control takes
and handles that same exception. Its presence is not the fatal regression.
The matching public PDB does not name the anonymous trampoline; an unrelated
nearest imported symbol does not identify it. It is not suppressed or patched.

`L/userenv-first-exception-03/first-chance/` preserves the initial capture.
Continuing to second chance captures the fatal exception at **0x0103a54f**,
`WlpExecuteNotify@4 + 0x132`, reading **0x308** through an invalid notification
context. EDI is **0x304**, ESI **0x308**, EBX **0x80000002**. Matching Winlogon
symbols identify `StartMachineGPOProcessing@4` at **0x0102f851** and its
UserEnv-140 call at **0x0102fae9**.

That call supplies five arguments: flags, token, event, HKLM and status callback.
SP3 UserEnv-140 is `ApplyGroupPolicy@20`. The rejected adapter kept source
private ordinal 140 unchanged, binding it to `DetermineProfilesLocation@4`.
Its `ret 4` leaves sixteen bytes on the stack. The callback epilogue then pops
token **0x304**, event **0x308** and HKLM **0x80000002** into saved registers.
The notification worker treats EDI as its context and faults at EDI+4. The
exact captured registers agree with that sequence. No evidence requires a
Winlogon structure-layout or security patch.

The minimal correction is this export permutation; original executable
sections, implementation RVAs and imports remain unchanged:

| SP3 ordinal | Source ordinal | Verified implementation |
| --- | --- | --- |
| 117 | 118 | `InitializeUserProfile@0` |
| 118 | 140 | `DetermineProfilesLocation@4` |
| 131 | 117 | `ShutdownGPOProcessing@4` |
| 140 | 131 | `ApplyGroupPolicy@20` |

All other private 100–158 bindings agree. Existing name-based relocation pins
the 49 named SP3 exports. **All 110 export bindings**, beyond availability,
are checked against source/native symbols and matching installed public PDB
symbols with OMAP address translation. No other stdcall argument-byte differences
are found in that comparison. `build/pdb_publics.py` verifies PE RSDS GUID/age.
The native older-format PDBs use supplied native CVDUMP; they are not treated as
MSF7. Debug metadata comes from Microsoft's HTTPS symbol server; URLs/hashes
are under `W/symbols/`. No runtime component download is used. Format references:
[Microsoft symbol server](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symsrv),
[LLVM MSF](https://llvm.org/docs/PDB/MsfFile.html),
[DBI streams](https://llvm.org/docs/PDB/DbiStream.html).

`build/native-userenv-build.cmd` independently rebuilds the original subtree in
`L/userenv-rebuild-01`: **53 files, five libraries, one DLL**, ten binplace
operations, zero result. It reuses prior RPC/RSOP and SDK-header prerequisites.
`build/userenv_sp3_compat.py` adds the corrected readonly export section and
verifies original section bytes, function RVAs, imports and non-export directories.

Three unavailable implementations still forward to unchanged original
`ue51sp3.dll`. They are not independently rebuilt. Only the first is the
cross-forest security function; the former description of all three as security
functions was incorrect:

| SP3 export | Matching symbol | Exact retained target |
| --- | --- | --- |
| 159 / `CheckXForestLogon` | `CheckXForestLogon@4` | `ue51sp3.CheckXForestLogon` |
| 200 | `CreateURLFile@36` | `ue51sp3.#200` |
| 201 | `DeleteURLFile@16` | `ue51sp3.#201` |

Original implementations/security checks are preserved. No success-returning
security stubs exist. Domain, cross-forest, enterprise GPO, roaming profiles
and complete SP3 semantic/security equivalence remain unverified.

## Artifacts and accepted matrix

| Artifact | SHA-256 |
| --- | --- |
| Rebuilt branded Explorer | `487830836b1543a2e8fd2600b0bb08fb9145d8bf303afbf9817d0151e4f8af1e` |
| Rebuilt raw UserEnv | `3197f5dff702e1a546fc4dfde4416fbc4a891e01b4fc722fd9f04f0eabf45d70` |
| Adapted accepted UserEnv | `72781a5be915a2aa0a31a6c61acb1173a5efafe19d8202bc8980b209fcaddf7b` |
| Original companion / UserEnv recovery | `9c5409ecbd2c3b89c80f0a59b96220178e790a7d78967c6281d56eb1965e9ecd` |
| Original branded Explorer recovery | `f632191a7ea07b09f4ebea506ec8c277938c1b87c39aac4bb24af724e396b643` |

| Tested stack | One-vCPU KVM | Two-vCPU KVM | One-vCPU TCG |
| --- | --- | --- | --- |
| Explorer alone, installed UserEnv | `explorer-integrated-kvm-03`: pass | `explorer-integrated-kvm-mp-01`: pass | `explorer-integrated-tcg-01`: pass |
| UserEnv alone, installed Explorer | `userenv-integrated-kvm-03`: pass | `userenv-integrated-kvm-mp-01`: pass | `userenv-integrated-tcg-01`: pass |
| Both components | `shell-userenv-combined-kvm-01`: pass | `shell-userenv-combined-kvm-mp-02`: pass | `shell-userenv-combined-tcg-01`: pass |

All nine frozen runs pass component, extension and reviewed GUI reports. Each
includes prior standard/pointer/session/network/service, Regsvc, MSGINA,
branding, Win32/MSI fixtures; actual mapped kernel/component identities; real
logoff/classic login and lock/unlock; Calculator/Notepad; exact unique Notepad
offline readback; fresh service shutdown notification; guest shutdown and image
check. Combined runs rerun the suite after authentication and also retain the
actual QMP `SHUTDOWN`, `guest=true`, `reason=guest-shutdown` event. A deliberately
invalid fixture password is visibly rejected in the combined KVM cycle; partial
frames elsewhere are not promoted as complete UI evidence.

New probes add **14 shell cases** and **14 fresh-profile cases**. The shell
probe reads actual Explorer's checksum, opens Start, checks active/configured
Luna, creates its own folder/file, opens it through ShellExecute, observes the
folder's list view/content, closes only its own window and removes the fixture.
The profile probe creates an unused standard local account, authenticates it,
calls LoadUserProfileW for a new profile, verifies its hive/path and registry
round trip, unloads/deletes the profile and removes the account. Existing XP25
credentials/policy stay unchanged. GINA's probe now reads UserEnv inside the
real interactive Winlogon, rather than relying on a separate process load.

Probe failures remain recorded. Standalone GetCurrentThemeName returns
`0x80070490` in the installed-SP3 control too; the Luna path is REG_EXPAND_SZ.
The corrected probe checks IsThemeActive and the configured path without OS
changes. A combined MP trial fails its single 700-ms menu observation; a manual
menu check succeeds. That trial is excluded. Fresh MP02 uses a bounded ten-second
poll, observes the menu after 109 ms and passes both suites. The precise cause
of the earlier observation failure is not established. Fixed preboot media
`W/test-media-04`/05 differ only in that bounded observation. Intermediate
console repaint frames remain alongside complete desktop/lock/Notepad frames.

Original recovery copies at `C:\xp25\recovery-explorer.exe` and
`recovery-userenv.dll` are checked after shutdown. Restore only the recorded
single original target in a stopped disposable child, then rerun tests. Frozen
accepted parents remain the immediate fallback. Components are tested individually
before creating the combined child; no reference or user VM is an integration target.

## Reproduction and engineering image

Use fresh names and the retained prepared native-build VM/toolchain. Generate
the Explorer patch CD and a separate NIC-free build child:

```bash
python3 build/prepare_shell_compat.py --output .work/shell-compat-next
python3 vm/native_build_lab.py --name shell-compat-build-next \
  --base .work/boot-debug-20261022/shell-native-build-03/disk.qcow2 \
  --media .work/shell-compat-next/native-shell.iso
```

Run `cmd /c D:\build.cmd C:\xpout\shell-compat-next` in that child. Require all
zero target results and the EXE, stop normally, and extract EXE/PDB/logs through
`vm/read_guest.py`. Apply the existing `prepare_branding.py --only-explorer`
resource transformation. For UserEnv, create a readonly CD containing
`build/native-userenv-build.cmd` as `build.cmd`, start a fresh prepared native
build child, run `cmd /c D:\build.cmd C:\xpout\userenv-next`, stop and extract.
Adapt only that rebuilt output:

```bash
python3 build/userenv_sp3_compat.py \
  --native .work/USERENV-EXTRACT/nt/ds/security/gina/userenv/main/obj/i386/userenv.dll \
  --reference .work/milestone-3-20261023/userenv-installed-inputs/WINDOWS/system32/userenv.dll \
  --output .work/userenv-compat-next
```

Build probes with `build/guest.py --probe shell|profile|gina` and the retained
XP SDK/toolchain. Media manifests/batch files define the exact full suites.
`vm/network_lab.py` creates private isolated children with one explicit
`--component` replacement. UserEnv's `--userenv-package` adds only its verified
original companion. Use `--cpus 2` and `--accel tcg` for other configurations.
Combined children start from accepted UserEnv parents and replace only Explorer.
Perform GUI and full probes, inspect using the matching kernel/map, resume,
freshly arm `D:\arm-shutdown.cmd`, request `vm/xp_lab.py DIRECTORY shutdown`,
and finish/extract only after normal shutdown. Require exact component, recovery,
profile, shell, captured identity and shutdown gates. Export/process-only results
cannot substitute for this guest evidence.

`W/components-manifest.json` records seven artifact variants, exact source recipes,
PE dependencies, fixes, twenty accepted experiments and earlier rejected runs.
Raw rebuilt UserEnv is classified as compiled, not the tested adapted artifact.
`W/compatibility-fixes.json` links patch/build/branding/interface/ordinal proofs.
Winlogon, three original UserEnv implementations, installed shell dependencies,
drivers and the previously documented supplied executive objects remain explicit
Microsoft dependencies. Source completeness/full reconstruction remain false.

```bash
python3 build/package_verified_desktop.py \
  --run .work/boot-debug-20261022/shell-userenv-combined-kvm-01 \
  --matrix .work/boot-debug-20261022/shell-userenv-combined-kvm-mp-02 \
  --matrix .work/boot-debug-20261022/shell-userenv-combined-tcg-01 \
  --provenance .work/xp-sp3-install-20261018/input.json \
  --components-manifest .work/native-shell-userenv-20261024/components-manifest.json \
  --output .work/xp25-engineering-next
python3 -m unittest discover -s tests -v
```

Packaging requires fresh passing matrix/GUI reports, identical retained stacks,
a frozen chain, sector equality, image integrity and component-manifest hashes.
It flattens without editing guest files or boot settings. The new artifact is
`W/engineering-image-02/XP25-Components-Engineering.qcow2`, SHA-256
`39112bbd46f89308180d651a94826808dee3a6acdcc18309b9af7c6d90340296`.
It has 32 GiB virtual capacity, 9,674,489,856 file bytes, no backing file and
read-only permissions. Sector comparison reports `Images are identical` and
`qemu-img check` passes. Its manifest records nineteen frozen ancestor hashes,
the accepted matrix and exact retained component stack. Always boot a disposable
writable child/copy. The previous image remains at SHA-256
`1263ec2b8816d9093249fd49a25a2a50eded2f7b05ae6c92f5d9b7d35a81d613`.
This is a private preinstalled engineering disk. A clean authorized Windows
Setup ISO remains a separate milestone; no redistribution or source-completeness
claim is made.

`L/shell-userenv-standalone-kvm-01` independently cold-boots a disposable child
whose entire backing chain is that child plus the new standalone disk. It stages
no component replacement. Both full suites pass, including the actual mapped
Explorer/UserEnv identities, fresh profiles, services, installers and networking.
Lock/unlock, Luna/Notepad and unique offline save readback pass, followed by
matching native-kernel inspection, freshly armed shutdown proof, the actual
guest-shutdown QMP event and image check. The packaged disk's hash remains
unchanged afterward. `W/engineering-image-02/independent-boot-proof.json` binds
the reports; `W/standalone-backing-proof.json` records the two-image chain.
Cold boot of the flattened artifact is additionally tested under one-vCPU KVM;
the complete pre-packaging component matrix covers KVM/MP/TCG above.

## Preservation and limits

`W/source-preservation.json` compares every file under `Source/XPSP1/NT` by path,
byte count and SHA-256: **277,863 files, 6,322,952,743 bytes**, unchanged manifest
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
`W/reference-preservation.json` verifies the earlier engineering disk and
`brand-final-tcg-01` reference. Every run checks its frozen parent, and packaging
rehashes the complete frozen chain after conversion. No reference disk is
opened writable.

`W/vm-preservation.json` shows all six inactive libvirt XML definitions unchanged,
including `XP25-Desktop` and `XP25-Anniversary`. The original `xp25-sp3` process
retains its PID, command hash and start time. One additional PID in the initial
process snapshot is no longer present; that snapshot does not identify its
name, and no lifecycle operation is issued to a user domain. No libvirt network
or domain setting is changed. New test networks use private namespaces without
an uplink. Source/build tools and guest components are not publicly distributed.

Thirty-five host checks pass, including every UserEnv binding against the
matching SP3 symbols for the final rebuilt native input, mismatched-PDB rejection,
deterministic export adaptation/code preservation, incomplete/stale runtime
evidence rejection and changed frozen-checkpoint rejection. These checks support
the recorded guest tests; they do not replace them. General software/hardware
compatibility, unexercised private shell interfaces, enterprise authentication,
sustained stability and complete independent reconstruction are not established.
