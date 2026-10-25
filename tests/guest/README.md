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
and the NT 5.1 identity. It then opens System Properties through `sysdm.cpl` and
records every General-page control's text, and whether the manufacturer and
model lines fit their controls. It leaves the dialog open. JSON lines go to the
file, and to COM1 when that opens. Without `--expect` every case is `observed`
with a `holds` flag; with it the QuoolAI values are gates and the exit code is
the number of failures. See [the OEM record](../../docs/xp25-winlogon-oem-branding.md).
