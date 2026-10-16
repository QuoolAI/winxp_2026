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

Exit 0 means its six implemented observations passed; it does not mean the full
regression suite passed. Exit 1 indicates a failed observation, and exit 3 means
no output destination accepted at least one record. Each JSONL case has its own
status and error. Login transitions, legacy games, security mitigations and
shutdown are explicitly `not_tested`, even when the process exits 0. Loopback
does not test NIC drivers, DNS, TLS or Internet access. Driver enumeration does
not prove correct initialization of any particular physical device.

No guest execution has been performed: there is no supplied bootable custom XP
image. The first runtime milestone is to collect these records with image hashes
and screenshots, then add explicit login/shutdown observations and application
fixtures. Do not reinterpret firmware-only QEMU results as guest passes.
