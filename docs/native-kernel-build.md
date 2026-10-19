# Native x86 kernel build: 2026-10-19

The supplied XP SP3 guest compiled and linked four checked x86 kernels from the
NT 5.1.2600.1106 reference copy. The reference `Source/` tree was not edited.
All binaries, source copies, transfer media, commands and logs remain private in
`.work/xp-sp3-install-20261018/`. [Installed guest baseline](xp-sp3-guest.md)

## Source preparation

The read-only UDF image came from the previously verified disposable
`.work/milestone-1-native-stage/NT` tree. Its reference manifest SHA-256 is
`9ff55c733e15a62c06c99db5c126f79886894c7e9b6734cea1358eb73656a151`.
Windows `xcopy` copied 277,863 files to `C:\nt`; a guest manifest comparison
found all expected paths and sizes, totaling 6,322,952,743 bytes, with zero
mismatches. This was a path/size comparison, not a guest hash of every file.

The source batch files have LF endings. Razzle initially failed with
`The system cannot find the batch label specified - ArgOK`. A private Perl
script, executed by the supplied Windows Perl 5.00503 tools, converted 2,544
`.cmd`/`.bat` files in **the guest copy only** to CRLF. No binary files were
skipped. `batch-crlf-expected.jsonl` records original and normalized SHA-256
values; `batch-crlf.log` records the guest changes. An offline read confirmed
that the guest's normalized Razzle matches its expected hash. The UDF image
retains the original bytes for rollback.

Razzle's first-use private `setenv.cmd` editor was closed with its template
unchanged. An accidental console command typed into that editor was discarded;
the extracted file confirms that it was not saved.

## Build environment corrections

The project wrapper passed quoted TEMP and binary-directory arguments to
Razzle. Razzle preserved those quotes inside environment values. NMAKE then
reported that it could not create an inline file in the quoted TEMP path.
The wrapper now passes those arguments without quotes after rejecting paths
containing spaces.

The original `build.exe` also returned zero despite child NMAKE failures.
The wrapper now checks for the observed NMAKE failure marker and nonempty
`build*.err` files. A failing compilation returned 1; the successful kernel run
returned 0. Neither result alone establishes an OS boot.

The original compiler executed as Microsoft C/C++ 13.00.9176 for 80x86. A
separate 465-byte smoke object and the full kernel build both establish native
compiler execution. No Wine, Linux or ReactOS runtime was used in the guest.

## Generated prerequisites

Kernel-only scope did not prepare several outputs normally produced elsewhere
in the original build graph. The following supplied tools and sources generated
them in the guest:

```bat
C:\nt\tools\x86\genlvl.exe -t C:\xpout\generated C:\nt\base\published
C:\nt\tools\x86\mc.exe -h C:\xpout\generated -r C:\xpout\generated C:\nt\base\busdrv\pci\pcicodes.mc
C:\nt\tools\x86\mc.exe -h C:\xpout\generated\isapnp -r C:\xpout\generated\isapnp C:\nt\base\busdrv\isapnp\message.mc
```

Generated `dpfiltercm.h` and `dpfiltercm.c` were copied beside `cmdat3.c`;
`dpfilter.c` beside `kddata.c`; `pcicodes.h` beside `pcip.h`; and `message.h`
beside the ISA PnP sources. These files came from the original generators and
inputs. No replacement implementations or API stubs were introduced.

With the same offline checked x86 Razzle environment, `build.exe -Z` also built
`base\boot\bootvid\daytona` and `base\boot\kdcom`. Their libraries satisfy the
kernel link dependencies. The resulting DLLs were retained; the first boot
test used the installed SP3 DLLs.

## Retained attempts

| Guest output directory | Observed result |
| --- | --- |
| `C:\xpout\kernel-01` | LF batch label failure; wrapper exit 2 |
| `C:\xpout\kernel-02` | Same failure before normalization; exit 2 |
| `C:\xpout\kernel-03` | Razzle runs after normalization; quoted TEMP causes NMAKE failures; old wrapper returns 0 |
| `C:\xpout\kernel-04` | Corrected wrapper; 1,927 files compiled, 72 libraries and one executable reported; missing generated prerequisites; exit 1 |
| `C:\xpout\kernel-05` | Debug-filter and PCI prerequisites resolved; ISA PnP header and boot-video library still needed; exit 1 |
| `C:\xpout\deps-01` | ISA PnP header generated; boot-video and debugger libraries built; no reported errors |
| `C:\xpout\kernel-06` | Four kernel variants linked; exit 0; no error log produced |

The last incremental run reports eight executable link operations and sixteen
binplacements. There are four kernel variants; repeated link operations are not
additional architectures. Logs and selected files were extracted read-only into
`native-extracted/`. Missing optional error logs are recorded as extraction
failures rather than fabricated empty logs. The complete command/QMP journal
is `commands.jsonl`.

## Inspected kernel outputs

All four files identify i386, native subsystem 5.1, OS 5.1 and file version
5.1.2600.1106. Resource flags `0x9` identify debug/private builds. Their PE
checksums match independent recomputation. Imports are `HAL.dll`, `BOOTVID.dll`
and `KDCOM.dll`. `kernel-inspection.json` and individual objdump reports retain
the evidence. Binutils warns that it ignores `IMAGE_SCN_MEM_NOT_PAGED` section
flags while displaying them; inspection did not rewrite the files.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `ntoskrnl.exe` | 3,378,176 | `fbb9dee4d6ca8d61603cd0e82bbbea2872a4a3db046091435fe214fce5c810eb` |
| `ntkrnlmp.exe` | 3,378,688 | `bc609975465db0f5790b4a56db6a9b4d4a1c1391362d15b0aadc0ed5209ef52f` |
| `ntkrnlpa.exe` | 3,446,784 | `81febf0d498d83d0ded02056d28cce0ebb4d6051301eed3872ec63a896a082cf` |
| `ntkrpamp.exe` | 3,446,784 | `d882dcb3f6f1e3b90d8255a035b1c451f991312d4aaa9dbd762b18231dcfe9b9` |

The filenames reflect the original UP/MP/PAE targets. For checked builds,
`ntoskrnl.inc` forces `NT_UP=0`, including the nominal UP target. These are
MP-enabled checked kernels; filenames alone do not establish runtime SMP
coverage. All guest tests in this record use one CPU.

The stopped build disk passed `qemu-img check`, was made read-only, and has
SHA-256 `45301e5c36a678955881721a1f0c9f1014cd2c2a872284bb11951fd3b91c2fd6`.
Its size is 8,138,260,480 bytes. The original SP3 backing-disk hash remains
`e64190c0c2314945d56cb78efa08bcda4551cb4247d6dde848c076a4cc0d776c`.
`build-checkpoint.json` records the disk chain and writable child creation.

## First source-kernel boot attempt

The nominal UP target was copied as `WINDOWS\system32\xp25krnl.exe`. Offline extraction
confirmed an exact match with the built kernel. The installed SP3
`ntoskrnl.exe` retained its original hash. A second boot.ini entry uses
`/kernel=xp25krnl.exe /sos /bootlog`; the original SP3 entry remains first and
default. The original boot.ini is preserved in `C:\xp25\boot.ini.pre-custom`.

The test used a separate child of the frozen build disk. Screenshots
`83-boot-test-menu.png` and `84-source-kernel-selected.png` record selection of
the custom entry. NTLDR then stopped at `System32\Drivers\Ntfs.sys`
(`85-source-kernel-startup.png`). No completed custom OS startup or login was
established in this attempt. QEMU's `running` status was observed at the error
screen; QEMU was stopped explicitly, not through a successful Windows shutdown.

The installed NTFS driver is present, has a valid PE checksum, reports
5.1.2600.5712, and hashes to
`fb3b88458f09951827c11d50a8be57769ce639a49115fa5dc084e22d5504a67a`.
Its imports require two exports absent from the rebuilt kernel:

- `SeAuditingFileEventsWithContext`
- `SeAuditingHardLinkEventsWithContext`

Both exports exist in the installed SP3 kernel. This establishes an import
incompatibility between that driver and the SP1-era source kernel.
`ntfs-import-comparison.json` retains the comparison. The first failed disk is
preserved as `boot-test-ntfs-mismatch.qcow2` with screenshots and command records.
The supplied NTFS source uses the older interfaces. Its build and the later
isolated tests follow below.

## Matching NTFS driver and checked HAL

The original targets `base\fs\lfs\mp` and `base\fs\ntfs\efs` produced the
missing NTFS link dependencies. `base\fs\ntfs\mp` then built successfully
(`C:\xpout\ntfs-03`, exit 0). The driver was installed under a new filename,
`System32\DRIVERS\xp25ntfs.sys`, and selected through the Ntfs service ImagePath
in the disposable test disk. The original SP3 `ntfs.sys` was retained.

The 817,280-byte driver identifies i386/native 5.1.2600.1106, has a valid PE
checksum, and hashes to
`7cbda223f981fa37b8de1a91cd6dd926347eaf3e26a888663df40af139cfdc06`.
All of its kernel imports exist in the rebuilt kernel. It also imports
`hal.dll` and `ksecdd.sys`; static import checks do not establish full runtime
compatibility. `matched-ntfs-inspection.json` retains the inspection.

The second isolated boot passed the loader's previous NTFS stop and entered the
source kernel, then halted at `xHalHaltSystem`. The kernel map, virtual memory
read and register capture establish `KiBugCheckData = [0x79, 2, 1, 0, 0]`:
`MISMATCHED_HAL`, checked kernel versus free HAL. This was an early kernel stop,
not completed OS startup. `boot-ntfs-test.qcow2`, screenshots 92–96, the map and
`commands.jsonl` retain its evidence. QEMU was explicitly quit afterward.

The original `base\hals\halacpi\apic` target then built checked `halaacpi.dll`
(`C:\xpout\hal-01`, exit 0). The installed SP3 HAL's OriginalFilename identifies
the same ACPI APIC UP family. The new file is copied as `xp25hal.dll`, with
`/hal=xp25hal.dll` added only to the experimental boot entry. Its 159,232 bytes
hash to `9850e46b38c71068f7b3046b59fd522902c5c9375b7c9519bd98e55256ce21ab`.
It identifies i386/native 5.1.2600.1106, debug/private flags `0x9`, a valid PE
checksum, and imports `ntoskrnl.exe` and `kdcom.dll`. Its kernel imports all
resolve statically. The installed copy exactly matches the build output.

After a recorded guest shutdown, `matched-hal-preboot.qcow2` passed image checks
and was frozen read-only: 68,157,440 bytes, SHA-256
`db90a110a0f5e1d23587a220a3bcd2b63a0434935581df80eed8593eaf79c99f`.
Its backing disk is the unchanged frozen native build disk. Each boot experiment
uses a new writable child; `dev-session.qcow2` remains the stable SP3 route.

## Checked HAL under KVM

The kernel/HAL/NTFS set advanced past loader enumeration, then reset before
login. A persistent QMP capture recorded `guest-reset`. The F8 automatic-restart
option did not retain the stop on screen. An initial post-reset RAM examination
was provisional and is not used to identify the primary exception.

A host GDB hardware breakpoint at the mapped `KeBugCheckEx` entry
(`0x80a2df30`) captured the live call before reset:

```text
KeBugCheckEx(0x8e, 0x80000003, 0x801023b1, 0x80ad148c, 0)
```

The exception is `STATUS_BREAKPOINT` at HAL RVA `0x23b1`. The original HAL code
writes the APIC task-priority register, reads it back, compares the values and
executes `int 3` on a mismatch in a checked build. The saved trap frame has
ECX `0x3d` (written) and EAX `0x30` (read). HMP's APIC state also reports TPR
`0x30`. This establishes the failed check under this KVM configuration; it does
not establish behavior on physical hardware. No instruction, assertion or
kernel safety check was patched out. `hal-bugcheck-live-gdb.log`,
`hal-bugcheck-kernel-virtual.bin` and the HAL disassembly retain the evidence.

## TCG experiment and current boundary

A fresh child of the same frozen preboot disk was started with `-accel tcg`
in place of KVM. Screenshots 127–129 record the source entry and named kernel/HAL
loading. The guest returned to startup menus without reaching a verified login.
Later retries reached the blue initialization screen (138), then returned to
the boot menu (139). No loaded-kernel identity or passing probe was collected
for that transition, so it is not promoted to a source-built OS boot.

The TCG breakpoint did not capture a primary bugcheck. Its exception trace is
retained as `tcg-exception-trace.log`, but tracing ended before the later reset;
the primary cause is unresolved. This experiment neither proves that TCG fixes
the APIC check nor establishes that it fails for the same reason as KVM.
Test QEMU processes were explicitly quit; those stops are not successful Windows
shutdowns. `source-boot-checkpoint.json` records final disk hashes and checks.

The supplied SP3 guest remains the verified runtime/build baseline. The kernel,
matching NTFS and checked HAL compilation milestones are complete; a completed
source-kernel login and a full original-system rebuild remain unverified. The
next debugging step is a controlled source-entry boot with continuous exception
capture and loaded-image relocation discovery, then a breakpoint at the actual
runtime bugcheck address. Do not infer a stable baseline from driver enumeration
or an initialization screen.
