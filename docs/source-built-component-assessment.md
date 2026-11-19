# Source-built Microsoft components: post-1106 security assessment (roadmap R-1)

Worktree `xp25-modernization`, after Milestone 8.4. Evidence root
`.work/r1-20261119/` (`W1`). XP25 builds 25 binaries from Microsoft's
5.1.2600.1106 (Service Pack 1 era) source
([audit](architecture-modernization-audit.md)). They therefore lack every fix
Microsoft shipped for them later: Service Pack 2 and 3, and the bulletins up to
the end of XP support in April 2014. Milestone 8.4 analysed only XP25's own
code. R-1 starts the same work for the Microsoft components that face untrusted
input and run privileged: `lsasrv.dll`, `services.exe`, `ws2_32.dll` and
`win32k.sys`. It adds `user32.dll` and `gdi32.dll`, which share `win32k.sys`'s
bulletins (MS05-002, MS07-017) and parse untrusted files.

## Method

1. **Which later fixes exist.** `build/bulletin_index.py` fetched all 1,001
   published bulletin pages MS02-001…MS14-085 from learn.microsoft.com (2 numbers
   were never used). It indexed them offline: title, date, CVE identifiers,
   whether Windows XP is in the affected-software table (483), and the components
   named by the title and the CVE titles. From 2008 on, file lists appear only in
   Knowledge Base articles, so a match is a candidate, not proof that the file
   changed.
2. **Is the defect in our source, and reachable in XP25.** Each candidate's own
   text (cause, attack vector) was read. Where Microsoft's description or public
   technical detail identifies a mechanism, the 1106 source was searched for it.
   Reachability was judged against the XP25 baseline: firewall on, SMB server and
   RDP off, no Active Directory, no IPsec policy.
3. **Classification.** *Confirmed* means located in our source. *Suspected* means
   Microsoft fixed it after 1106 and the mechanism was never published, so it
   cannot be located from the source alone. *Not applicable* means it needs a
   component or service that XP25 does not have. *False positive* means the
   indexer's keyword matched a different file.
4. **Fixes** follow Milestone 8.2's pipeline (`components/cve/`, applied to a
   disposable copy by `build/cve_source.py`; `Source/` is never written). Host
   tests compile the real functions from both trees under AddressSanitizer. The
   native control and patched builds come from the frozen build VM
   (`cc5156ee…`). A symbol-level comparison shows the patch is the only change,
   and guest runs use overlays of the accepted 8.2 image.

```sh
python3 build/bulletin_index.py fetch --output .work/r1-20261119/bulletins/html
python3 -I build/bulletin_index.py index .work/r1-20261119/bulletins/html .work/r1-20261119/bulletins/index-02.json
python3 -I build/bulletin_index.py report .work/r1-20261119/bulletins/index-02.json
```

Candidates per component (Windows XP affected). The CVE totals count every
identifier in those bulletins, some of which belong to other files.

| Component | Bulletins | CVE identifiers in them |
| --- | --- | --- |
| `lsasrv.dll` | 8 | 22 |
| `services.exe` | 0 | 0 |
| `ws2_32.dll` | 1 | 2 |
| `win32k.sys` | 36 | 207 |
| `gdi32.dll` / `user32.dll` | 15 | 59 |
| CSRSS / `winsrv.dll` (not assessed) | 10 | 19 |
| kernel (`xp25krnl.exe`, not assessed) | 48 | 208 |

## `lsasrv.dll`

| Bulletin | CVE | Microsoft's cause | XP25 | Class |
| --- | --- | --- | --- | --- |
| MS04-011 | CVE-2003-0533 | DsRole log overflow | Fixed and installed in 8.2 | Confirmed, fixed |
| MS04-044 | CAN-2004-0894 | "Incomplete validation of connection information by LSASS" (local) | Reachable by any logged-on user | **Suspected** |
| MS08-002 | CVE-2007-5352 | "LSASS does not properly handle specially crafted LPC requests" (local) | Reachable by any logged-on user | **Suspected** |
| MS09-059 | CVE-2009-2524 | NTLM integer underflow during authentication, remote denial of service | Needs inbound NTLM authentication; XP25 serves none (SMB server, RDP off) | Suspected, not reachable from the network |
| MS09-066 | CVE-2009-1928 | LDAP stack exhaustion in ADAM/AD | No ADAM or AD in XP25 | Not applicable |
| MS09-069 | CVE-2009-3675 | Malformed ISAKMP over IPsec | No IPsec policy in XP25 | Not reachable |
| MS10-068 | CVE-2010-0820 | LDAP heap overflow in ADAM/AD | No ADAM or AD | Not applicable |
| MS11-014 | CVE-2011-0039 | "Specially crafted authentication request" (local) | Reachable by any logged-on user | **Suspected** |

MS04-044's other identifier, CAN-2004-0893, is an LPC message-size check in the
**kernel**, which XP25 also builds from source.

## `services.exe`

No bulletin after 1106 changed the Service Control Manager on Windows XP.
MS06-011 (CVE-2006-0023) was about the *stored* DACLs of six services. Their
descriptors were read offline from the 8.2 image's SYSTEM hive
(`W1/tools/service_dacls.py`): `SSDPSRV`, `NetBT`, `upnphost`, `SCardSvr`,
`Dhcp` and `Dnscache` carry the hardened SP2-era DACLs. Authenticated Users and
Power Users have no change-config, write-DAC or delete right on any of them. The
one non-administrator write right is Local Service's change-config on
`upnphost`, which matches Microsoft's own corrective DACL in MS06-011. The 1106
SCM's default DACL for services without a stored one (`scsec.cxx`) gives
Authenticated Users only read and user-defined control. **No finding.**

## `ws2_32.dll`

The single candidate, MS06-041 ("Winsock hostname", CVE-2006-3440), updated
`dnsapi.dll` and `rasadhlp.dll`, not `ws2_32.dll`. **False positive.** A targeted
review of the paths that handle remote-derived text found no defect:

- `inet_addr` (`addrconv.cpp`) hands the terminated string to
  `RtlIpv4StringToAddressA` under an exception handler.
- `DTHREAD::CopyHostEnt` sizes the per-thread buffer from the blob. Its `WORD`
  size record can only under-record and force a reallocation, never an overflow.
- `UnpackHostEnt`/`FixList` turn blob offsets into pointers without checking
  them. They trust the in-process name-service provider (the SP3 `mswsock.dll`
  and `dnsapi.dll`, which parse the DNS data). That is a trust assumption, not a
  defect.

Not reviewed: `getaddrinfo`/`getnameinfo` (`addrinfo.cpp`, 2,776 lines),
`WSAStringToAddress`, and the provider catalog (administrator-controlled
registry).

## `win32k.sys`, `user32.dll`, `gdi32.dll`

Thirty-six XP bulletins name win32k: MS03-045, MS04-011, MS04-031, MS04-032,
MS05-002, MS05-018, MS05-053, MS07-017, and 28 bulletins from MS09-065 to
MS14-015. All of those 28 are "Kernel-Mode Drivers" bulletins except the
combined MS12-034. "Windows Kernel" bulletins whose fixes went into
win32k (MS08-025, MS08-061, MS09-025 and others) are counted under the kernel,
since only their KB articles listed files. The GDI/USER client list adds
MS06-001, MS07-046, MS08-021, MS08-071, MS12-034 and MS13-089. MS04-028,
MS09-062, MS11-029 and MS13-054 are GDI+ (`gdiplus.dll`, an SP3 binary): false
positives for `gdi32`.

Confirmed in our source and **fixed** (details below):

| Finding | Component | Microsoft reference | Reach |
| --- | --- | --- | --- |
| Every GUI process keeps a `SECTION_ALL_ACCESS` handle to the section that holds GDI's handle table (kernel object addresses) | `win32k.sys` (`gre/cleanup.cxx`) | MS07-017, matches CVE-2006-5758's description | Any local program |
| Animated-cursor sequence indexes and starting step accepted unchecked; the animation code indexes the frame and rate tables with them | `win32k.sys` (`ntuser/kernel/acons.c`) | Class of MS05-002 / MS07-017 ("format validation … cursors, animated cursors, and icons") | Any local program; ANI files through `user32` |
| ANI chunks copied with their file-declared size: `anih` into a 36-byte stack header, `rate`/`seq` into tables sized from the frame and step counts; more frames stored than declared; file-map bounds checks that wrap on 32-bit | `user32.dll` (`ntuser/client/acons.c`) | MS07-017 CVE-2007-0038 and the related checks | Any program that loads a cursor or icon file, for example a web page's cursor |
| WMF playback installs an abort procedure from a `META_ESCAPE`/`SETABORTPROC` record | `gdi32.dll` (`ntgdi/client/mfplay16.c`) | MS06-001, CVE-2005-4560 | Any program that renders a WMF |
| A keyboard layout's NLS table selects functions by unchecked index (`NLSFEProcIndex`) and type (`NLSFEProcType`) from win32k's function tables | `win32k.sys` (`ntuser/kernel/fekbd.c`) | MS10-073, consistent with public analyses of CVE-2010-2743 | Any user who loads a keyboard layout |
| A new path record is linked into the path before its forward link is set; an allocation failure later in `pprFlattenRec` leaves a stale pointer in the path | `win32k.sys` (`ntgdi/gre/pathflat.cxx`) | MS13-053, consistent with public analyses of CVE-2013-3660 | Any local program that flattens paths |

Everything else in these lists is **suspected**: fixed by Microsoft after 1106,
mechanism never published. Microsoft's own text names the MS10-073 and MS13-053
vulnerabilities but not their mechanism. The two found here match public
analyses, and other publicly analysed XP win32k flaws may also be present. XP25's
win32k has none of the other 2003–2014 fixes. Treat any local program as able to reach kernel code
with known, unfixed defects. This is the largest residual risk in XP25.

### The fixes

| Patch (`components/cve/`) | Change |
| --- | --- |
| `r1-win32k-gdi-section-handle` | `GdiProcessCallout` opens the section with `OBJ_KERNEL_HANDLE` and `SECTION_MAP_READ`, maps the read-only view and closes the handle. The 1106 code opened it as a user-accessible `SECTION_ALL_ACCESS` handle and never closed it. A second, writable mapping needs no protection change, so the section's `SEC_NO_CHANGE` (set in `hmgrapi.cxx`) did not help. |
| `r1-win32k-ani-sequence` | `_SetCursorIconData` rejects zero frame or step counts and any sequence entry ≥ the frame count, and starts the animation at step 0. |
| `r1-user32-ani-chunks` | `ReadChunk` takes the destination size. `anih` must be exactly one header and appear once, with frames and steps ≤ 0xFFFF and steps ≠ 0. `rate`, `seq ` and `fram` only after `anih`, never larger than their tables. No more frames than declared. `ReadFilePtr*`, `ReadFilePtrCopy` and `SkipChunk` compare with the bytes left instead of forming wrapping pointers. `ReadIconGuts` stops at a directory entry outside the file. |
| `ms06-001-gdi32-wmf-setabortproc` | `PlayMetaFileRecord` skips a `SETABORTPROC` escape record. |
| `r1-win32k-kbd-nls-index` | `GenerateNlsVkKey`, `GenerateNlsVkAltKey` and `xxxKENLSProcs` check the index and type against their tables. A key with an invalid entry is passed on unchanged. |
| `r1-win32k-pathrec-next` | `EPATHOBJ::newpathrec` sets the new record's `pprnext` to NULL. The `pathobj.cxx` caller already did so itself. |

One candidate was **withdrawn** during review. `SEC_NO_CHANGE` on the GDI view
looked like the CVE-2006-5758 fix, but the section is already created with
`SEC_NO_CHANGE`, so every view refuses protection changes. The open handle is the
actual exposure.

**Host proof** (`tests/test_cve.py`, `R1User32AniTests`; `tests/cve/r1_user32_ani.c`).
`LoadAniIcon` and the RIFF/file-map helpers are compiled verbatim from both
trees under ASan, with a file map of exactly the file's size. The chunk bodies
are filler; only sizes and order are malformed.

| Layout | 1106 | Patched |
| --- | --- | --- |
| valid (2 frames, 2 steps, rate and seq) | loads | loads, identical |
| `anih` declared 100 bytes | stack-buffer-overflow, WRITE of 100 in `ReadFilePtrCopy` | rejected |
| `rate` 64 bytes for 1 step | heap-buffer-overflow, WRITE of 64 | rejected |
| `seq ` 64 bytes for 1 step | heap-buffer-overflow, WRITE of 64 | rejected |
| 4 frames for 1 declared | heap-buffer-overflow, WRITE of 8 in `LoadAniIcon` | rejected, created frames destroyed |
| `rate` before `anih` | (table address from NULL; not run) | rejected |
| chunk larger than the file | rejected | rejected |

**Host proof** (`R1Win32kKeyboardNlsTests`; `tests/cve/r1_win32k_kbdnls.c`).
`GenerateNlsVkKey`, `GenerateNlsVkAltKey` and `xxxKENLSProcs` are compiled
verbatim. The function tables are modelled with the entry counts of the real ones
(16 and 3, read from `fekbd.c`).

| Layout entry | 1106 | Patched |
| --- | --- | --- |
| valid (type normal → index 1; type toggle → alt index 2) | dispatches | dispatches identically |
| function index 16 (one past the table) | global-buffer-overflow, READ of 8 in `GenerateNlsVkKey` | key passed on, nothing called |
| alt index 255 | UBSan: index 255 out of bounds for the 16-entry table | key passed on, nothing called |
| function type 3 (one past the table) | global-buffer-overflow, READ of 8 in `xxxKENLSProcs` | key passed on, nothing called |

The other win32k changes and the gdi32 change have no host harness (kernel and
GDI internals). They are shown by the symbol comparison below and by the guest
runs.

**Native builds.** The media come from `build/prepare_cve.py`. The control
build `r1-core-control-01` (`a20f44e9…`) has no patches. Patched build
`r1-core-patched-01` (`00a87ffa…`) has the first four. Patched build
`r1-core-patched-02` (`096f3e9a…`) has all six, and is the build the guest runs
use. The build VM `cc5156ee…`
rebuilt `ntgdi\gre`, `ntuser\kernel`, `kmode`, `ntuser\client` and
`ntgdi\client` (`daytona`) with `build -cZ`: `XP25_CVE_BUILD_EXIT=0`, no
compiler warnings or errors, 445 compilations each.

| Binary | Installed (8.2 image) | Control | Patched |
| --- | --- | --- | --- |
| `win32k.sys` | `b28afb2f…` | `37650ef6…` | `f698e04d…` (02; 01 was `a88f8e26…`) |
| `user32.dll` | `a51976dd…` | `9824eea4…` | `4cccacd3…` (02; 01 was `8ad1f8e0…`) |
| `gdi32.dll` | `09698075…` | `4618d8b4…` | `13e538d3…` (02; 01 was `4e66d6e7…`) |

- `build/cve_compare_builds.py reproduce installed control`: **reproduced** for
  all three. After link-time-stamp and import-hint normalization there are 0
  other differing bytes. The control build is what XP25 ships.
- `cve_compare_builds.py symbols control patched-02`:
  - `win32k.sys`: code changes only in the six patched functions:
    `GdiProcessCallout`, `_SetCursorIconData`, `GenerateNlsVkKey`,
    `GenerateNlsVkAltKey`, `xxxKENLSProcs` and `EPATHOBJ::newpathrec`.
    `KbdNlsFuncTypeAlt`, `NlsKbdInitializePerSystem`,
    `NlsKbdSendIMENotification`, `W32pProcessCallout` and `vSrcTranCopyS1D8`
    differ only in relocated call targets and data addresses (checked by
    disassembly). The rest is 374 import thunks, 18 imported kernel data
    pointers, 3 checked-build assertion strings with shifted line numbers, and
    4 new warning strings.
  - `user32.dll`: changes only in `acons.obj` (the patched file). `ReadChunk@12`
    became `ReadChunk@16`. The only other difference is one relocated
    address in a uuid.lib constant.
  - `gdi32.dll`: changes only in `PlayMetaFileRecord`, plus one relocated
    address in a dispatch table.

### In the guest

`tests/guest/r1core_probe.c` (`f6f3f984…`; kernel32, user32 and gdi32) runs as
XP25's Startup program. It reports its own section handles, loads and draws every
stock cursor, and plays a WMF and its EMF conversion. It never maps anything
writable and uses no malformed file. Fresh overlays of the accepted 8.2 image
(`5a84781f…`) were used. *Base* is the image as shipped. *Patched* stages build 02's
`win32k.sys`, `user32.dll` and `gdi32.dll`.

```sh
W=.work/r1-20261119
$W/run-probes.sh r1-base-up-02 up base        # and r1-up-03 up patched, r1-mp-01 mp patched, r1-tcg-01 tcg patched
$W/regression.sh                               # the probes on MP and TCG, then proof UP/MP/TCG
```

| Run | Handle to the GDI table section | Cursors (34 `.ani`, 150 `.cur`, 361 steps drawn) | WMF / EMF |
| --- | --- | --- | --- |
| `r1-base-up-02`, 1106 binaries, 1 vCPU KVM | **one**: handle `0x774`, access `0xF001F` (`SECTION_ALL_ACCESS`), committed, 1,060,864 bytes, the size of the read-only view | all load | both draw |
| `r1-up-03`, patched, 1 vCPU KVM | none | all load | both draw |
| `r1-mp-01`, patched, 2 vCPU KVM | none | all load | both draw |
| `r1-tcg-01`, patched, TCG | none | all load | both draw |

The only other section handle (64 KB, `SEC_BASED`) is present in every run.
Security-lab `proof` with the patched trio, AI build 17 and the R-0 Winlogon
passed 35/35 on 1-vCPU KVM, 2-vCPU KVM and TCG (`r1-proof-{up,mp,tcg}-01`).
That is the same stack as R-0's `r0-proof-*`, so the comparison isolates these
three files.

Kept as evidence with notes (`probe-note.json`):
- `r1-base-up-01` and `r1-up-01` ran the first probe build. It looked for
  `SEC_NO_CHANGE` in `NtQuerySection`'s attributes, which the kernel never
  reports (`querysec.c`), so their GDI-section result is invalid. Their
  section-handle counts (2 base, 1 patched) and their cursor and metafile
  results are valid.
- `r1-base-up-02` exits 1 by design: it records the defect.

Not tested in the guest:
- An NLS (Far East) keyboard layout, the path that `r1-win32k-kbd-nls-index`
  changes. The guests use the US layout.
- A path-flattening allocation failure (`r1-win32k-pathrec-next`).
- Malformed cursor, icon or WMF files: on purpose, the guest runs use only
  ordinary input.

## Residual risk and next steps

- **win32k / GDI / USER**: dozens of suspected local privilege escalations
  remain. The way to locate undisclosed fixes is a function-level comparison of
  the 1106 binaries with Microsoft's final XP builds of the same files. Where
  XP25 does not depend on its own build, shipping Microsoft's SP3 binary would
  close many of them at once.
- **lsasrv**: three suspected local EoPs (MS04-044, MS08-002, MS11-014). Same
  approach.
- **kernel and CSRSS** (48 and 10 candidate bulletins) were not assessed. The
  kernel is the next target, starting with MS04-044's LPC size check.
- `ws2_32`'s `getaddrinfo` path still needs a review.
