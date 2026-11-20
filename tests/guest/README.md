# Native XP guest checks

Build on the prepared host:

```bash
python3 build/guest.py --toolchain .work/toolchains/mingw-binutils/usr/bin \
  --output .work/next-probe
```

The resulting `xp_probe.exe` is an x86 PE 5.1 executable using only kernel32,
user32, advapi32 and ws2_32 imports. It has no C runtime dependency. Compilation
and import checks are not evidence of successful execution on XP.
Every named import is also checked against the locally supplied XP SDK import
libraries. Those libraries are read only and are not copied into the output.
This build step belongs on the private development host, not public CI.

In an isolated, supplied XP installation, after interactive logon:

```bat
xp_probe.exe --serial > C:\xp25-probe.jsonl
```

`--serial` additionally emits records through COM1 at 115200 baud for the QEMU
serial log. The probe runs bounded loopback UDP, writes/reads/removes its own
temporary file and volatile registry key, checks the shell PID belongs to
Explorer, and queries active driver services. It creates no external network
connection, installs no service, and requests no shutdown. Run as the same user
as the desktop; permissions can legitimately cause failures.

Driver enumeration consumes 4 KiB pages and follows the service resume handle.
It accepts valid partial results accompanying `ERROR_MORE_DATA`, rejects stalled
continuation, and stops after at most 256 pages. A `driver_services` record gives
the number of running services observed and pages consumed. This fixed the
original one-allocation failure on the supplied XP SP3 guest.

Exit 0 means its six implemented observations passed; it does not mean the full
regression suite passed. Exit 1 indicates a failed observation, and exit 3 means
no output destination accepted at least one record. Each JSONL case has its own
status and error. Login transitions, legacy games, security mitigations and
shutdown are explicitly `not_tested`, even when the process exits 0. Loopback
does not test NIC drivers, DNS, TLS or Internet access. Driver enumeration does
not prove correct initialization of any particular physical device.

The corrected probe was executed on the [supplied XP SP3 guest](../../docs/xp-sp3-guest.md)
under Administrator and XP25, and after rebooting its build overlay. All six
observations passed; driver enumeration returned 70 running services across two
pages. The original failure, serial records, executable hash and installed-disk
hash are retained. Manual login and shutdown observations are separate from the
probe's four `not_tested` cases. No bootable custom XP image or game baseline has
been established.
# Additional boot-compatibility probes

`build/guest.py --probe pointer` builds `pointer_probe.exe`; it checks real
EncodePointer/DecodePointer exports, concurrent round trips, process separation
and rejected cookie-query arguments without logging cookie values.
`--probe session` builds `session_probe.exe`; it verifies XP25's primary token,
Explorer's matching user/logon session and the visible Default desktop.
Both write JSON observations to COM1. Run each separately and wait for its
completion marker. Neither replaces the standard filesystem/application tests
or independently proves a login transition. See
[the source-desktop record](../../docs/source-desktop-milestone.md).

`build/guest.py --probe network` builds `network_probe.exe`. It verifies IPv4
conversion, TCP/UDP payload loopback, required running services, an RTL8139
adapter's controlled DHCP address, DNS for `xp25.test`, and TCP/HTTP to
`10.25.0.1:8080`. Use it only with the private namespace harness in
[`vm/network_lab.py`](../../vm/network_lab.py). It writes 17 observations to
COM1 and exits nonzero on a failure. Its guest dependencies are XP's Kernel32,
User32, Advapi32, Ws2_32 and Iphlpapi; it has no C runtime dependency.

`build/prepare_network_tests.py` packages all four probes only after checking
their successful build results, current source hashes and executable hashes.
The CD's `regress.cmd` runs each probe in sequence and records its exit status;
`stability.cmd` repeats the network probe ten times and records the number of
failed runs. These commands do not infer login transitions or shut down the
guest. Check the full suite's completion marker before the next UI/debugger
operation. See the [networking milestone](../../docs/native-networking-milestone.md)
for guest restart, authentication, Notepad, shutdown and packet evidence.

`build/ai_build.py --probe` builds `ai_probe.exe` for the XP25 AI milestone;
`vm/ai_lab.py` stages and starts it. Without arguments it drives the installed
ClippyAI and RoverAI windows, command lines and the Explorer Search command
through window messages and writes one `{"ai_case":...}` record per gate to
COM1, followed by `AI_PROBE_COMPLETE passes=N failures=M`; the exit code is the
number of failures. `provider <gateway-hex-key>` configures the gateway in
ClippyAI Settings with typed keys and checks requests, consent, signed
replies and failure fallback; `dpapi` records user-scope `CryptProtectData`,
machine-scope DPAPI and Credential Manager behavior as notes; `cpu` records
how a single busy thread is accounted (unpinned and pinned to each processor),
sampled like ClippyAI's `process_list`; `burn` is the single-threaded CPU load
fixture; a trailing `slow` multiplies every timeout by
four for TCG. See [the milestone record](../../docs/xp25-ai-clippyai-roverai.md).

`build/guest.py --probe oem` builds `oem_probe.exe` (kernel32, user32, advapi32,
gdi32). `oem_probe.exe [--expect] --out <file>` records `oeminfo.ini`'s
`[General]` values, OEM logo files, Help and Support's `HelpSvc\OEMInfo` copy
and the NT 5.1 identity. It then opens System Properties and records every
General-page control's text. It checks:
- that every single-line text fits its control and no text line overlaps another;
- that, on all seven tabs, every visible control that shows something lies inside its page;
- that the sheet's width fits the screen;
- that the OEM model fits the 124-DLU Computer line at 96, 120 and 144 DPI.

It leaves the dialog open. Without `--expect` every case is `observed`, with a
`holds` flag; with it, the QuoolAI values are gates and the exit code is the
number of failures. JSON lines go to the file, and to COM1 when that opens.
`--rename NAME --out <file>` sets the computer name with `SetComputerNameExA`.

`build/prepare_vm_config_media.py` packs the probe with `vmconfig/vm-before.cmd`,
`vm-verify.cmd` and `vm-restore.cmd` for the interactive VMs, and
`vm/vm_config_results.py` gates the results offline. See [the OEM
record](../../docs/xp25-winlogon-oem-branding.md) and [the VM configuration
record](../../docs/xp25-vm-configuration.md).

`build/security_build.py` builds `security_probe.exe` (Kernel32, User32, Advapi32,
Netapi32, Shell32, UserEnv, Winsock 2, msvcrt) together with the XP25 security tools.
`security_probe.exe admin [--hardened] [--xp25-winlogon] [--tools <dir>]` is run
by the logged-on administrator. It creates a temporary ordinary account with a
random password, runs itself as that account through the Secondary Logon
service and again with a restricted token of the administrator inside a Job
Object, and removes the account and its profile afterwards. Each unprivileged
run attempts the real operation — writing system files, the kernel image and
hives, `HKLM` run, policy and service keys, reconfiguring or starting services,
enabling privileges, opening LSASS, Winlogon and the XP25 broker for injection,
opening the logon desktop, asking the SYSTEM broker to stop the firewall,
running `XP25Sec apply|rollback` — and passes a case only on the expected
denial. The administrator side checks that legitimate administration still
works, that every baseline service is disabled and stopped, that a disabled
service does not start, and that the Security log recorded the account
management and failed logon the probe itself caused. Without `--hardened` the
baseline-dependent cases are `observed`, not gates; a case whose object does
not exist is `not_run`, never a pass. Records go to COM1 as
`{"security_case":...,"context":"admin|ordinary_account|restricted_token"}`
followed by `SECURITY_PROBE_COMPLETE context=... passes=N failures=M`; the exit
code is the number of failures. `security_probe.exe power shutdown|restart|logoff`
calls `ExitWindowsEx`, because `shutdown.exe` does not work under the XP25
Winlogon. Since Milestone 8.1 the unprivileged contexts also try the firewall
service, its driver, keys and device, `netsh`/`net stop`, 21 machine-wide
autostart and hijack keys, system files and directories, the All Users
folders, 13 broker requests and a takeover of the broker's pipe name; the
administrator restarts anything an unprivileged case managed to stop. Further
modes: `fwcheck <tag>` (the firewall as the guest sees it: service and driver
running, start type, profile values, who may control the service);
`listen <port> <dir> [broadcast]` (TCP banner and UDP echo, optionally a
broadcast from its UDP port every half second; never answers its own
broadcasts or echoes; stops when `<dir>\listener.stop` exists);
`hostwait <label> [seconds]` (waits until the lab's observer has finished the
observation the suite asked for with `XP25_HOST_REQUEST=<kind>:<label>`);
`desktop <file> [--hardened] [slow]` (a standard user's own session: profile,
shell identity, Luna, files, programs, IE, ClippyAI, RoverAI, broker, shutdown
right; results to the file and, where the account may open it, COM1);
`apps <file> [slow]` (the programs and games installed with Windows, each in
a console of its own: window, responsiveness, close, crash detection through
Windows Error Reporting); `aireset` (ends RoverAI and ClippyAI the way a user
does between repeated AI suites). Use it only through
[`vm/security_lab.py`](../../vm/security_lab.py); see
[the regression record](../../docs/security-regression.md).

`ai_probe.c` sends the requests whose completion it then checks with
`SendMessageTimeoutW`, so a case is decided when ClippyAI has finished the step
(minimize, restore, settings OK), not after a fixed sleep, and records each
step's duration as an `ai_timing` note; `ai_probe.exe reset` ends ClippyAI and
RoverAI.

# Milestone 8.4 probes

Built with `build/guest.py --probe NAME`; each writes JSON records to COM1 and is
run from a Startup fixture by `vm/security_lab.py`
([record](../../docs/optimization-opportunities.md)).

* `clippyexit` (kernel32, user32): three cycles of starting ClippyAI, asking for
  a command that needs approval, waiting for the approval dialog and choosing
  Exit (`WM_COMMAND` `IDM_EXIT`). Records how long the process takes to end and
  its exit code, and checks the declined command never ran. Exit 0 when every
  cycle ends within 5 s with code 0.
* `gscookie` (kernel32, user32, advapi32, shell32): `module=rva` arguments give
  the RVA of `__security_cookie` from the build's PDB (`build/gs_check.py`). For
  every process with the module loaded, the probe reads the cookie and checks it
  differs from the compiler's pre-initialization value. Values themselves are not
  printed.
* `roverbench` (kernel32, user32, shell32): loads the given `xp25agent.dll` and
  times `rover_store_load`, `rover_index_scan` over the real file system and
  `rover_index_serialize`, without saving. The DLL's exports are `__stdcall`
  (the NT build's `/Gz`); the probe declares them `WINAPI`.
* `idle` (kernel32, user32, advapi32): lowers this session's screen-saver
  timeout to 60 s (not saved) and stays idle for 2 minutes. It then measures, for
  1 minute, how often COM1 can be opened and how much `native-winlogon.log`
  grows, restores the timeout and sends one Shift key press. Exit 0 when COM1
  stayed available (≥ 90%) and the log grew by at most 1 KB.
* `screensaver` (kernel32, user32, advapi32): roadmap R-0, run at each XP25
  logon by `vm/winlogon_screensaver_probe.py`, which supplies the console input.
  First session: an idle timeout of N s (argument, default 20) and `ssstars.scr`,
  then four savers: not secure; secure, ended by a key; secure, ended by
  Ctrl+Alt+Del; on a station locked with Win+L. For each it records whether USER
  reports a running saver (`SPI_GETSCREENSAVERRUNNING`) and which input desktop it
  can open (`Screen-saver`, `Default`, or none while locked). It then sets
  `.DEFAULT`'s timeout to N, restores its own and logs off. The second session
  restores `.DEFAULT` (600 s). Each case record is written 2 s after its last
  transition, so Winlogon's own COM1 lines go first. Exit 0 when every case passed.
  ([record](../../docs/winlogon-screen-saver.md))
* `r1core` (kernel32, user32, gdi32): roadmap R-1, for the rebuilt `win32k.sys`,
  `user32.dll` and `gdi32.dll`. It only observes and makes ordinary API calls:
  nothing is mapped writable and no malformed file is used.
  - It lists this process's section handles. It reports how many refer to the
    GDI shared handle table: committed, not image- or file-backed, sized like
    the read-only view at `PEB->GdiSharedHandleTable`. `NtQuerySection` does not
    report `SEC_NO_CHANGE`, which is why the size is used.
  - It loads every `.ani` and `.cur` file in `%windir%\Cursors` and draws each
    animated cursor through its steps.
  - It records a WMF, then plays it and its EMF conversion into a bitmap.
  Exit 0 when the cursors and metafiles work and no GDI section handle is held.
  ([record](../../docs/source-built-component-assessment.md))
