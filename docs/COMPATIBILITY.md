# Compatibility matrix

No custom XP image has booted. `Not tested` means no installation, execution or
stability evidence exists; it is not a prediction of compatibility. Guest runtime
and hardware support must cite an image hash, exact version, environment and logs.

## Runtime regression coverage

| Requirement | Implemented observation | Current execution status |
| --- | --- | --- |
| Kernel boot | QEMU serial/screenshot capture; guest OS identity probe | Firmware only; custom XP boot blocked |
| User login | Probe intended to run after logon | Login transition not implemented/tested |
| Explorer | Check shell PID resolves to `explorer.exe` | Probe compiled; guest not run |
| Registry | Volatile HKCU DWORD roundtrip with cleanup | Probe compiled; guest not run |
| Filesystem | Temporary file write/read/cleanup | Probe compiled; guest not run |
| Networking | Bounded IPv4 UDP loopback roundtrip | Probe compiled; no NIC/DNS/TLS test |
| Legacy Win32 applications/games | Application fixtures not supplied | Not tested |
| Driver initialization | Enumerate active kernel driver services | Probe compiled; device functionality untested |
| Shutdown | No shutdown request from the probe | Not implemented/tested |
| Security regressions | Runtime dependency gate for probe | No guest mitigation/security validation |

`tests/guest/xp_probe.c` reports six implemented observations separately from four
explicitly untested areas. Its exit 0 must not be interpreted as passing this
entire table. [Guest instructions](../tests/guest/README.md)

## Software targets

No specific modern application release has been selected or installed. A target
family does not imply all releases or architectures are feasible.

| Target | Installation | Launch | Functionality | Stability |
| --- | --- | --- | --- | --- |
| Original Explorer/Luna/Control Panel | Not tested | Not tested | Not tested | Not tested |
| XP-era DirectDraw/Direct3D games | Not tested | Not tested | Not tested | Not tested |
| Legacy Win32 installers/applications | Not tested | Not tested | Not tested | Not tested |
| Python 3 | Not tested | Not tested | Not tested | Not tested |
| Git | Not tested | Not tested | Not tested | Not tested |
| Current TLS client | Not tested | Not tested | Not tested | Not tested |
| Chromium-based browser | Not tested | Not tested | Not tested | Not tested |
| Newer C/C++ runtime | Not tested | Not tested | Not tested | Not tested |
| .NET application/runtime | Not tested | Not tested | Not tested | Not tested |
| Contemporary developer utility | Not tested | Not tested | Not tested | Not tested |
| One-Core-derived API-set aliases | Not installed | Not tested | 28/arch statically checked | Not tested |

## Hardware and deployment targets

| Target | Verified evidence | Guest support status |
| --- | --- | --- |
| QEMU i440fx, BIOS, IDE, Cirrus | Both profiles execute SeaBIOS and QMP | XP boot not tested |
| Multicore/SMP/modern CPU instructions | Existing source paths only | No new support claim |
| UEFI/GPT/NVMe/AHCI/USB 3.x | No guest experiments | Unverified |
| Modern ACPI/interrupt controllers | Existing ACPI/HAL code only | Unverified |
| Modern GPU/multiple displays/passthrough | Host VFIO node exists | No device or driver validated |
| Ethernet/Wi-Fi/IPv6/Bluetooth | No network-adapter tests | Unverified |
| EC2 | XP omitted from supported import list; i386 imports discontinued | Blocked, no deployment |

EC2 constraints were checked against [AWS import requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html).
Do not mark a target supported based on a source symbol, an API stub, a successful
link, a firmware screen or a device node alone.
