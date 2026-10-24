# XP25 visible branding

This pack adds the Windows XP 25th Anniversary Edition name to selected en-US
UI resources on disposable children of the verified native SCM/SMSS desktop.
It does not change the Windows compatibility identity. The installed Microsoft
UI binaries remain dependencies; editing their resources is not reconstruction
of those components from original source.

## Verified checkpoint, 2026-10-23

The en-US pack passes the recorded one-vCPU KVM, two-vCPU KVM and one-vCPU TCG
matrix. Each final guest boots the matching original source kernel, authenticates
XP25 after logoff, loads Explorer/Luna, passes the 54 established component and
network observations, 17 branding/legacy observations and five MSI build/install/
state/uninstall statuses. Calculator computes 2+2; Notepad saves unique text
verified offline. Native SCM receives the shutdown control, and QMP observes
normal guest shutdown before the image is frozen and checked.

| Experiment under `.work/boot-debug-20261022/` | Scope / result |
| --- | --- |
| `brand-baseline-kvm-01` | Unbranded native SCM/SMSS control; final corrected fixtures pass |
| `brand-system-kvm-01` | System Properties / shared About / Winver only; passes |
| `brand-explorer-kvm-02` | Explorer added alone; passes with fixed preboot CD |
| `brand-shell-kvm-01` | Shell32 Help resource added alone; passes |
| `brand-login-kvm-01` | LogonUI added alone; full branded one-vCPU KVM passes |
| `brand-final-kvm-mp-01` | Full branding with previously verified original MP kernel/HAL; passes |
| `brand-final-tcg-01` | Full branding under TCG; passes |

The final protected identity is NT **5.1**, build **2600**, x86, workstation,
suite mask 256 and **Service Pack 3**, matching the unbranded control. All three
final raw readonly identity snapshots match the control SHA-256
`f529d72bbc712989ee8935d3ae87cb4be852fb5ed469d492719bbf256bb071ce`.
All six modified UI files and all six original guest recovery copies are
rehashed after shutdown. Native SCM and SMSS remain intact. Retention does not
establish general compatibility of signed-file repair or installation workflows.

The final reproducible package is `.work/branding-20261023/patched-ui-06/`.
The guests used fixed `test-media-07/branding-tests.iso`; the final tracked
packager reproduces its complete payload byte for byte in `test-media-09/`.
`branding-manifest.json`, `gui-review.json`, resource audits, preparation/build
logs, per-run `branding-results.json` / `component-results.json`, serial/QMP
journals, private DHCP/DNS/HTTP evidence and retained binaries stay under
`.work/`. The full Source inventory retains manifest SHA-256
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`;
eleven frozen reference image hashes and all five existing libvirt XMLs are
unchanged. `XP25-Desktop` remains shut off and unmodified; these branded images
are separate disposable lab checkpoints. All task lab guests are shut down.

Twenty-eight focused host checks pass. No general third-party application,
game, hardware, security, actual high-DPI desktop or non-English compatibility
claim follows from these fixtures. Actual classic-menu rendering remains
unverified. Existing security balloons and the 640x480 menu item-count balloon
can overlap screenshots; warning policies and menu geometry were preserved.

Earlier failed probe iterations remain recorded. The Win32 fixture originally
used an existing volatile test-key parent and inherited the CD file's readonly
attribute; it now uses its own key and removes its own copied file correctly.
Calculator's cross-process Edit text needs WM_GETTEXT and trailing-space
normalization. The first MSI fixture omitted its Media table and returned 2228/
1603 in both baseline and branded guests; the corrected registry-only package
installs and uninstalls in both. `brand-explorer-kvm-01` has inconsistent batch
output after live CD changes and is rejected; a new fixed-CD child passes.
The stale menu label is resolved by the targeted MUI cache refresh described
below. No branding compatibility regression is reproduced in the passing
matrix. Failed images are retained and never promoted. Reverse-order binary
restore/readback succeeds offline for all stages; recovery boot and the cache
helper's restore path are not separately certified.

## Resource boundaries

`branding/en-US.json` supplies independent display strings. The preparation tool
recognizes the exact reviewed layouts and captions, rejects other languages,
format substitutions, control characters and oversized strings, and writes only
under `.work/`. There is no global replacement of “Windows XP”.

| Location | Resource edit | Limits and preserved behavior |
| --- | --- | --- |
| System Properties | `sysdm.cpl`, dialog 101, new private static control 0x7f25 | Two lines in the unused left-hand gap; original version/product/OEM controls unchanged |
| About Windows and ShellAbout users | `xpsp1res.dll`, dialog 14352, new private label | Full edition name; dialog grows 12 DLU and existing text/buttons move down; license text unchanged |
| About Windows title | `winver.exe`, string 101 | Compact “Windows XP25”; original Winver uses `TCHAR szTitle[32]`, so the full edition name is deliberately a separate label |
| Classic and modern Start menu | `explorer.exe`, menu 204 and string 7021 | “XP25 Help”; command IDs, accelerators and menu alignment preserved; existing Start button caption unchanged |
| Help automation command | `shell32.dll`, string 12709 | Matching compact Help command name, original command and icon retained |
| Graphical login | `logonui.exe`, UIFILE 1000 and private string 4000 | Full edition name in the original 80-pixel blue header; original account controls and branding bitmap retained |

The source audit uses `shell/osshell/winver/winver.c`,
`shell/cpls/system/general.cpp`, ShellAbout's original dialog initialization,
Explorer/desktop2 resource definitions, Shell32's `IDS_AUTOCM_HELP` and
`shell/ext/logondui/logon.cpp`. Winver's compact title is 12 UTF-16 units;
the full edition name is 35. LogonUI's resource reader allows 100 characters.
The private labels use `SS_NOPREFIX`, avoiding accidental mnemonic parsing.
The classic MENUEX caption is padded to its original length to preserve DWORD
alignment. Start-menu labels are shorter than the original 17-character caption.

Only the supplied en-US/1033 pack is supported. The reviewed strings are ASCII,
safe through both ANSI/CP1252 and UTF-16 paths; the PE reader/writer handles
UTF-16 lengths, including surrogate pairs. Other locales require separate
resource and font/layout audits. Character bounds alone cannot prove pixel fit:
custom strings require new guest rendering and compatibility tests.

The original Luna theme, logos/bitmaps, fonts and existing system controls are
retained. This does not recolor or replace every Microsoft notice or icon.
Boot-loader/kernel/version strings and application metadata remain unchanged.
The shared ShellAbout label also applies to callers of that dialog, whose own
application title is preserved.

## Executable and identity protections

`build/pe_resources.py` serializes resources into their dedicated section. Five
edited modules fit the original allocation. LogonUI extends only its final
resource section; executable sections are never shifted. PE checksums are
recomputed. Installation verifies all non-resource section bytes/layouts,
normal/delay imports, exports, non-resource data directories and every original
VERSIONINFO payload. Unreviewed resource changes are rejected.

These resource edits necessarily change file/catalog hashes. Original Microsoft
Authenticode/catalog validity cannot be claimed for the changed files. The pack
does not disable Windows File Protection, signature checks, activation or other
licensing mechanisms. Retention is checked after guest shutdown; this is not a
claim that every future repair/trust workflow accepts modified files.

The offline installer writes no registry values. The OS `ProductName` remains
`Microsoft Windows XP`. Probes compare GetVersion, GetVersionExA/W,
RtlGetVersion, VerifyVersionInfoA/W, system architecture, CMD's version output
and raw readonly identity values against an unbranded control. The captured
registry scope includes CurrentVersion/build/CSD/BuildLab, ProductType and
ProductSuite, ProductId/DigitalProductId and WPAEvents/OOBETimer. Raw records
remain private and are compared without printing license data. Matching these
values proves those values were preserved; it is not a new activation or
licensing implementation.

XP caches localized shell names persistently. The existing profile had
`HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache\@explorer.exe,-7021`
set to the original Help caption. Original `shell/shlwapi/regw.cpp` confirms
that `SHLoadIndirectString` reads this cache before loading a DLL resource.
`refresh-menu.vbs` backs up and removes only that reviewed display-cache value;
Explorer repopulates it from the branded resource after logoff/login. No CLSID,
command, account setting or compatibility identifier is changed. This is a
per-profile refresh, not deletion of the whole cache. The same script's
`--restore` option restores its saved caption; restore the binary resource as
well when reverting the menu branding.

## Reproduction and recovery

Use new output/run names for every attempt. Never run a reference disk writable,
modify `Source/`, or use `XP25-Desktop` as an integration/test disk. The prepared
host, supplied binaries/tools and frozen native-component checkpoints are
required. No Microsoft files are fetched by these tools.

```bash
python3 vm/read_guest.py FROZEN_DISK .work/brand-inputs \
  /WINDOWS/system32/sysdm.cpl /WINDOWS/system32/xpsp1res.dll \
  /WINDOWS/system32/winver.exe /WINDOWS/explorer.exe \
  /WINDOWS/system32/shell32.dll /WINDOWS/system32/logonui.exe
python3 build/prepare_branding.py --inputs .work/brand-inputs/WINDOWS \
  --config branding/en-US.json --output .work/brand-package
python3 build/install_branding_overlay.py --base FROZEN_DISK \
  --package .work/brand-package --stage system --output .work/brand-system
```

Boot a fresh network-lab child of that staged disk, using the established
matching original kernel/HAL, native Winsock helper, SCM and SMSS. Require the
existing full regression suite, actual GUI review, branding probes, installers
and normal shutdown before progressing. Apply `explorer`, then `shell`, then
`login`, each individually to a frozen verified checkpoint. The stage installer
checks the expected original file hash, preserves host and guest originals,
reads the installed bytes back, hashes the unchanged parent and freezes its
new staged input. It never edits a live guest or its backing disk.

```bash
python3 build/guest.py --toolchain .work/toolchains/mingw-binutils/usr/bin \
  --probe branding --output .work/branding-probe-next
python3 build/prepare_branding_tests.py --probe .work/branding-probe-next \
  --core-media .work/milestone-3-20261023/test-media-04/media \
  --output .work/branding-tests-next
```

Attach the resulting ISO **before boot**, and keep it fixed during batch
execution. Wait for `STARTUP_REGRESSION_FINISHED` before keyboard input. In the
guest, `D:\verify-branding.cmd --system` tests the intermediate stages;
`--branded` additionally checks the login resource. The suite runs the identity,
font-metric and Calculator probes, a self-contained Win32 install/run/uninstall
fixture, a registry-only MSI install/uninstall and the SCM shutdown fixture.
The MSI's version condition requires native x86 NT 5.1; its ProductName belongs
only to that fixture. It does not author the OS ProductName.

For an existing profile, first run `cscript //nologo D:\refresh-menu.vbs`, then
log off and authenticate again. The script fails on unexpected cache content,
keeps `C:\xp25\branding-menu-cache-original.txt`, and supports `--restore`.
The prepared fixture expects the reviewed default branding strings.

Review System Properties, Winver, Start menu and login screenshots; explicitly
log off and authenticate again, rerun `D:\regress.cmd`, edit/save a Notepad
file, rerun branding/installer tests and request normal guest shutdown. Record
the live source-kernel checksum with `vm/inspect_native.py` and resume with QMP
`cont` after inspection. Only `xp_lab.py ... finish` after QMP reports
`shutdown` freezes the tested disk. Extract retained files and run both
`vm/component_results.py` and `vm/branding_results.py` against the control.
GUI observations remain separate from automated gates.
Final `branding_results.py` checks also require `--notepad-marker` with the
exact unique text saved in that guest; inherited files cannot satisfy that gate.

To revert a stage, retain the failed child and restore into another child:

```bash
python3 build/install_branding_overlay.py --base FROZEN_FAILED_DISK \
  --package .work/brand-package --stage login --restore \
  --output .work/brand-login-recovery
```

The same option works for each stage and checks both patched and original
hashes. Restore in reverse stage order to return every resource to its original
bytes. Retest the recovered child before use. The unbranded reference and
previous verified checkpoints always remain recovery options.
