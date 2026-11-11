# One-Core-API analysis and reuse

Inspected revision: [`9eb3c31de9460c1ccce3f6a10c9c4a704f032514`](https://github.com/shorthorn-project/One-Core-API-Source/tree/9eb3c31de9460c1ccce3f6a10c9c4a704f032514).
The pin is recorded in `build/onecore.lock.json`; the fetched source is retained
at `.work/upstream/one-core-api`, including its original license and credit files.

This repository provides useful compatibility code and candidate implementations
for missing components. We have reused its host tooling and export specifications
to build isolated API-set DLLs. Winlogon, services and kernel extensions have not
been integrated into the XP source or installed in a guest.

Under the Anniversary Edition preservation requirements, the ReactOS core
implementations are references rather than planned replacements for Microsoft's
Winlogon, service controller or kernel. Reuse currently consists of host tooling
and isolated API-set aliases, without a ReactOS or Wine guest runtime dependency.

## What the repository contains

| Upstream area | Relevance to this workspace | Current disposition |
| --- | --- | --- |
| `sdk/tools/spec2def/spec2def.c` | Converts architecture-specific export specifications into linker definitions | Compiled and used on Linux |
| `oca/api-sets/*.spec` | Provides API contract DLL names and forwarding targets | All 245 examined; 28 contracts built per architecture |
| `oca/extensions/kernelex`, `ntext` | Implements additional kernel32/NTDLL APIs, including synchronization extensions | Candidate follow-up; substantial implementation dependencies |
| `oca/wrappers`, `oca/new-dlls` | Wraps existing libraries and provides additional DLL implementations | Retained for future import-driven compatibility work |
| `base/system/winlogon` | ReactOS logon implementation corresponding to one missing XP component | Source candidate; binary compatibility untested |
| `base/system/services` | ReactOS service control manager; original XP target later located at `base/screg/sc/server` | Excluded as a core replacement; binary compatibility untested |
| `ntoskrnl`, `hal`, `boot` | ReactOS system foundation | A separate OS implementation, not an established XP kernel replacement |

The project documents XP SP3, Server 2003 SP2 and XP x64 SP2 as runtime targets.
This workspace's headers identify XP SP1, 5.1.2600.1106. The upstream README
requires RosBE 2.1.6 and Visual Studio 2010/2012 for its supported build path.
Those requirements apply to the full One-Core-API build; the small Linux
forwarder experiment below uses a separate build path. The README's compatibility
claims have not been reproduced here. [Upstream README](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/README.md)

## What was actually reused

`build/onecore.py` compiles the pinned upstream `spec2def` tool using native GCC,
preprocesses this checkout's `base/win32/client/kernel32.src` for the selected
architecture, and generates a linker definition for every tracked API-set spec.
It builds a contract only when every export is a named forwarder to a symbol
declared by that architecture's XP kernel32 export source. Local implementation
entries, stubs, other target DLLs, absent symbols and invalid contracts are
excluded. A contract with even one unresolved entry is excluded in full.

The script checks the upstream commit, the host tool's source hash and tracked
checkout modifications. It enumerates specifications from the pinned Git tree,
so an extra untracked `.spec` file cannot enter the build. It creates output
outside both source trees and refuses to reuse an existing output directory.

| Check | x86 | amd64 |
| --- | --- | --- |
| Specifications examined | 245 | 245 |
| DLLs linked and inspected | 28 | 28 |
| Contracts outside the verified kernel32-only scope | 216 | 216 |
| Invalid contracts excluded | 1 | 1 |
| Source-declared kernel32 exports | 942 | 956 |
| PE format | PE32 / i386 | PE32+ / x86-64 |
| OS and subsystem header versions | 5.1 | 5.2 |
| Runtime loading / application compatibility | Untested | Untested |

The resulting DLLs include debug, memory, datetime, legacy threadpool and heap
contracts. These are aliases to existing exports: they do not implement new
synchronization primitives, a new threadpool or other missing modern APIs. For
example, the debug contract forwards `DebugBreak`, `IsDebuggerPresent`,
`OutputDebugStringA` and `OutputDebugStringW` to kernel32.

Artifacts are in `.work/onecore-baseline-final/{x86,amd64}/dlls/`. Each adjacent
`result.json` contains every selection/rejection, source and binary hashes,
tool versions and runtime status. `build.log` records commands and diagnostics. `inspection/` retains
independent MinGW objdump output. Export names and forwarder targets, architecture,
zero entry point and version headers are checked after linking. Timestamps are
disabled; the regression test builds the x86 DLLs twice in different directories
and verifies identical hashes.

Native GCC reports warnings in the unchanged upstream `spec2def` source. These
are retained in `build.log`; the tool and selected DLL builds completed successfully.

These checks establish reproducible linked artifacts. They do not establish that
the installed XP kernel32 has the declared exports, that XP's loader will resolve
the contracts, or that an application will run. The amd64 export declarations in
this NT 5.1 tree also do not establish a complete XP x64 product baseline.

## Concrete integration obstacles

The pinned `kernelex/CMakeLists.txt` invokes `spec2def` for `kernelbase.spec`, but
that file is absent from the pinned repository. Also,
`api-ms-win-core-file-l1-1-0.spec` repeats `GetFileInformationByHandle`; our build
rejects that contract rather than emitting conflicting exports. These were
observed directly in the fetched revision; no full upstream CMake build was
attempted. [Kernel extension build definition](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/oca/extensions/kernelex/CMakeLists.txt),
[file contract specification](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/oca/api-sets/api-ms-win-core-file-l1-1-0.spec)

The synchronization contract refers to APIs absent from this XP export surface,
including targets in `kernelex`. Its definitions alone cannot provide working
SRW locks, condition variables or address waits. The implementations span
`kernelex/synch.c` and `ntext/rtl/synch.c`, making this a separate implementation
and runtime-testing task. [Synchronization contract](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/oca/api-sets/api-ms-win-core-synch-l1-2-0.spec)

Inventory correction, 2026-10-23: the original XP SCM target exists at
`base/screg/sc/server`; the earlier absence finding used a different path.
Its native build is still unverified. The project rules exclude replacing
Microsoft Winlogon/SCM with ReactOS or Wine implementations. The following
dependency findings explain why these upstream implementations are not used.

Winlogon requires ReactOS headers, Wine support, generated WinReg RPC server code,
GINA callbacks and logon/session behavior. Services requires generated SVCCTL RPC
code, NDK headers and service/security interactions. Their CMake files use the
ReactOS build macros, not this XP tree's NMAKE `sources` format. Their presence
makes replacement experiments possible; it does not close the corresponding XP
source gaps. [Winlogon build definition](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/base/system/winlogon/CMakeLists.txt),
[services build definition](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/base/system/services/CMakeLists.txt)

## Reproduce the isolated experiment

The current checkout and local toolchain are already prepared. Neither requires
system-wide installation. From the workspace root, choose fresh outputs:

```bash
python3 build/onecore.py --upstream .work/upstream/one-core-api \
  --binutils-dir .work/toolchains/mingw-binutils/usr/bin \
  --arch x86 --output .work/next-onecore/x86

python3 build/onecore.py --upstream .work/upstream/one-core-api \
  --binutils-dir .work/toolchains/mingw-binutils/usr/bin \
  --arch amd64 --output .work/next-onecore/amd64

python3 -m unittest discover -s tests -v
```

For a new checkout, fetch the exact pinned revision into a fresh directory:

```bash
git init .work/upstream/one-core-api
git -C .work/upstream/one-core-api remote add origin https://github.com/shorthorn-project/One-Core-API-Source.git
git -C .work/upstream/one-core-api fetch --depth 1 origin 9eb3c31de9460c1ccce3f6a10c9c4a704f032514
git -C .work/upstream/one-core-api sparse-checkout set oca sdk base/system/winlogon base/system/services
git -C .work/upstream/one-core-api checkout --detach 9eb3c31de9460c1ccce3f6a10c9c4a704f032514
```

The build needs native GCC and the appropriate MinGW `ld` and `objdump`.
If installed on PATH, omit `--binutils-dir`. On this Linux host the following
packages were downloaded and extracted privately with `dpkg-deb -x`:

| Package | Version | Download SHA-256 |
| --- | --- | --- |
| `binutils-mingw-w64-i686` | `2.41.90.20240122-1ubuntu1+11.4` | `5236ef254532c1f4ebddbce898e884fe9cc1ac4803092211ec615cbdeba7aafb` |
| `binutils-mingw-w64-x86-64` | `2.41.90.20240122-1ubuntu1+11.4` | `28bfabbf64a68813a56360bca056072af9ff71ef4090a4b8a8a085afcda3e4dd` |

At the One-Core checkpoint, 10 checks passed; later counts are in
[PROGRESS.md](PROGRESS.md). The integration test needs the local upstream
checkout and toolchain; it skips when those are absent. Native XP compilation
and a Windows runtime test still need a prepared build guest or suitable media,
as described in the [baseline runbook](build-vm-baseline.md).
