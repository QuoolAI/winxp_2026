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
