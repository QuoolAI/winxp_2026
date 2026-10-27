# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ground rules

`AGENTS.md` is authoritative; read it first. The rules most often relevant while editing:

- `Source/XPSP1/NT` is the immutable reference tree (NT 5.1.2600 QFE 1106, x86). Never edit it,
  build in it, or write output inside it. Several scripts refuse output under `Source/`. Its
  integrity is tracked by the manifest SHA-256 `9ff55c73…a151` in `docs/architecture.md`.
- All generated output, toolchains, upstream trees, guest disks and evidence go under the
  git-ignored `.work/`. Scripts refuse to overwrite an existing output directory, so use a fresh
  path every run (e.g. `.work/<topic>-<date>/<name>-NEW`).
- Never replace Microsoft core components with ReactOS/Wine/Linux code, and never fabricate
  success. For example, the Winlogon activation policy deliberately fails closed with error 120.
  Don't "fix" that by forcing an allow.
- Don't push, deploy, or send anything to public CI. Commit completed milestones locally using
  explicit paths (no `git add -A`), since `.work/` and stray logs sit at the repo root.
- Evidence levels are distinct: a PE that compiles, a process that starts, a guest that boots
  and a completed login/desktop are separate claims. Docs must state exactly which one was observed.

## Host tests (Linux)

There are no Python package dependencies. Tests use the system `cc`, and some use the private
MinGW toolchain at `.work/toolchains/mingw-binutils/usr/bin` or `qemu-system-i386`; they skip if
those are missing.

```bash
python3 -m unittest discover -s tests -v                       # full suite (41 tests)
python3 -m unittest discover -s tests -p test_winlogon.py      # one file
python3 -m unittest discover -s tests -p test_winlogon.py -k SessionEngineTests   # one class/test
```

`tests/` is not a package, so `python3 -m unittest tests.test_x` does not work. Use `discover -p`.

The Winlogon C tests (`tests/winlogon_*.c`) are compiled by `tests/test_winlogon.py` as strict
C89 (`-std=c89 -pedantic -Wall -Wextra -Werror`) against `components/winlogon/*.c`, and must
print `failures=0`. Sanitizer run of the session coordinator:

```bash
cc -std=c89 -pedantic -Wall -Wextra -Werror -fsanitize=address,undefined -DXP25_SESSION_TEST=1 \
  -I components/winlogon tests/winlogon_session.c components/winlogon/{session_engine,policy,state}.c \
  -o .work/<fresh>/session-tests && .work/<fresh>/session-tests
```

## Native builds and guest testing

The Linux host can't run the NT toolchain (no `cmd.exe`). Native builds run inside a private
32-bit XP SP3 build VM. The pattern used throughout `build/` and `vm/` is:

1. `build/prepare_*.py --output .work/...` copies only the XP25 sources plus a `.cmd` driver from
   `build/native-*-build.cmd` into an ISO (via `xorriso`), along with a hashed `manifest.json`.
2. `vm/native_build_lab.py --name <fresh> --media <iso>` boots a disposable, NIC-free qcow2
   overlay of a frozen build image. Media appears as `D:`.
3. `vm/xp_lab.py <experiment-dir> run 'cmd /c D:\build.cmd C:\xpout\<name>'` drives the guest
   over QMP. The `.cmd` copies sources to `C:\nt\...`, runs `razzle.cmd offline` and `build.exe -cZ`,
   and reports `XP25_*_BUILD_EXIT=<n>` on COM1 (serial.log). Then run `shutdown` and `finish`.
4. `vm/read_guest.py <disk> <out> <guest paths...>` extracts the PE/PDB/logs read-only.

A zero exit code isn't proof of a build. Check `native.log` for `nmake.exe failed` and inspect
the PE. Runtime tests use `vm/network_lab.py` with a frozen verified image, the standard probes
and `--component <guest path> <binary>` to install one replacement into a fresh overlay. Use
`--cpus 2` (MP kernel/HAL) and `--accel tcg` for the KVM-UP / KVM-MP / TCG matrix.
`vm/restore_winlogon.py` builds a recovery child from the verified parent. Never repair a
failed disk in place, and never touch libvirt user VMs. Full reproduction commands are in
`docs/native-winlogon.md` ("Build and isolated reproduction").

Runtime experiments boot a fresh overlay of a hash-verified engineering image with exactly one
replaced component. Overlays launched through `vm/isolated_network.py` get an RTL8139 NIC in a
private namespace (DHCP 10.25.0.10, DNS `xp25.test`, HTTP `10.25.0.1:8080`). A run only counts as
shut down when QMP reports `SHUTDOWN` with `{"guest": true, "reason": "guest-shutdown"}`. Failed
runs are frozen with a `failure.json`, never repaired or deleted. The per-milestone harness
(`.work/winlogon-licensing-20261025/{launch-native,lifecycle,desktop-power,finish-normal}.py`)
decides gates from the guest's own serial records, not from screenshots. QEMU UI input is
unreliable under load: verify a dialog is up before typing, and expect lost keys under TCG.

To diagnose a hung guest, `vm/capture_memory.py` pauses it, saves the registers and raw physical
memory, then resumes. `vm/inspect_threads.py` walks processes and threads with the matching kernel
`.map`, reporting wait reasons, waited-object names and user-mode frames. `build/typelib_dump.py`
recovers COM interface vtables from a binary's embedded type library.

Guest probes (`tests/guest/*.c`) are cross-compiled with
`build/guest.py --toolchain .work/toolchains/mingw-binutils/usr/bin --probe <name> --output .work/...`.
It verifies an i386 PE with 5.1 subsystem headers, no C runtime, and an exact allowed import-DLL
set, with each import checked against `Source/.../public/sdk/lib/i386`. See `tests/guest/README.md`
for probe semantics and exit codes.

## Architecture: XP25 Winlogon (`components/winlogon`)

This is the main active development area. It's an independent Winlogon written from scratch
because `ds/security/gina/winlogon` is absent from the source. It hosts the original MSGINA
(WLX 1.4). It's built natively by `sources` with `/W4 /WX` and `-DXP25_PRODUCTION_WINLOGON=1`.
Its layering:

- **Portable C89 core (host-testable, no Windows headers):** `state.c/.h` is the phase/event
  state machine. Facts are supplied only after a native operation succeeds. `policy.c/.h` is the
  fail-closed admission check. `session_engine.c/.h` is the coordinator that orders
  profile → policy → environment copy → secure desktop → notifications → GINA shell → identity
  check → Default desktop, plus lock/unlock/logoff/power/recover, through a `WL_SESSION_DRIVER`
  function table. `environment.c` and `bootkey_codec.c` are bounded parsers.
- **Native adapters (`platform.h`, Win32/NT APIs):** `main.c` (startup, window station and
  desktops, SAS), `gina.c` (MSGINA load and dispatch table), `session.c` (UserEnv profile, token
  and environment, and binds the single static native driver into the engine), `session_native.c`
  (shared token, process and environment helpers), `policy_native.c` (real
  `NtLockProductActivationKeys`, then reports `WlPolicyUnavailable`/120), and `security.c`,
  `notify.c`, `bootkey.c` (SYSKEY exchange with LSASS).
- **Test boundary:** test doubles exist only in `tests/winlogon_session.c` and the separate
  native test executable (`build/prepare_session_tests.py` → `wlsession_test`, with
  `tests/guest/session_*.c`). `policy.h` makes `XP25_PRODUCTION_WINLOGON` + `XP25_SESSION_TEST` a
  preprocessing error, and a host test verifies that guard. There is deliberately no runtime,
  registry or command-line test-mode selector. Keep it that way.

Licensing admission is decided by the installed `licdll.dll` COMLicenseAgent (`policy_native.c`),
using SP3 Setup's own call sequence. Never substitute a forced, cached or WMI-derived result.
Much of Winlogon's contract is private and undocumented: user32 exports marked `; winlogon`
(`LoadLocalFonts`, `UpdatePerUserSystemParameters`), MSGINA ordinals in
`public/internal/ds/inc/msginaexports.h`, and logon-process hotkeys. The original Winlogon's
import table (`.work/winlogon-session-lifecycle-20261025/original-winlogon-imports.json`) is the
checklist. `docs/winlogon-desktop-session.md` lists what is still missing, such as Terminal
Services session state and the Welcome screen. Notice values from `winwlx.h` are easy to misread:
`WLX_SAS_ACTION_NONE` is 2, not 0.

Ownership rules documented in `session_engine.h` matter: the environment copy transfers to
the driver on `activate`/`restart_shell` entry even on failure, and `end_processes` success
means user processes are actually gone. When adding a native source file, update
`components/winlogon/sources`, and also `build/prepare_session_tests.py` if the test executable
needs it.

The rest of the repo is build/VM tooling around the reference tree: `build/inventory.py`,
`stage.py` and `attempt.py` (hashed inventory, disposable source copy, protected native
launch), `build/onecore.py` (pinned One-Core-API forwarder experiment, `onecore.lock.json`),
`build/prepare_native_*.py` and `apply_*_compat.py` (original-component rebuild media and
compat shims), `branding/` with `prepare_branding.py` (reversible XP25 branding), and `vm/`
(QEMU/QMP lab harnesses and result collectors). `docs/architecture.md` maps NT components to
`Source/` paths.

## Documentation is part of every change

After any build or guest experiment, update `docs/PROGRESS.md` (newest checkpoint at the top)
and `docs/COMPATIBILITY.md`, plus the relevant milestone doc in `docs/`. Record the exact
commands, SHA-256 hashes of inputs and outputs, `.work/` evidence locations, failures (keep
them, don't delete them), and precise limitations. Hardware and software stays "Not tested"
until it's observed in a recorded guest.
