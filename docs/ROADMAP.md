# Incremental roadmap

Every milestone needs affected interfaces, build evidence, guest regression
results and a rollback route before changing a working guest. No bootable custom
baseline exists yet, so none can currently be promised to survive a kernel patch.

| Milestone | Concrete acceptance | Current state |
| --- | --- | --- |
| 1. Native build/boot baseline | Hash inventory; protected source copy; recorded compiler/build attempts; custom boot or precise blockers; QEMU diagnostics | Supplied SP3 guest verified; native kernels linked; native dependencies built; isolated boot blockers retained |
| 2. Native guest regression runner | Cross-compile XP-only probe, inspect dependencies, execute in isolated XP and collect serial records | Six checks pass on supplied SP3; enumeration fixed using recorded failure; manual login/shutdown observed |
| 3. First original-kernel link | Windows build guest; compile kernel/HAL/boot dependencies; retain PE hashes and linker logs | Four checked x86 kernels linked and inspected; matching NTFS, checked HAL and boot-video/KDCOM built |
| 4. First custom OS boot | Bootable original-XP payload; startup, login, Explorer and shutdown evidence | Matching NTFS and checked HAL built; KVM stops at HAL APIC priority readback assertion before login |
| 5. Legacy application baseline | Select supplied game/application fixtures; record graphics, input, audio, timers and stability | Guest available; no application/game fixtures or accelerated graphics validation |
| 6. API extensions | Import-driven selection, complete implementations, ABI tests and application-local rollback | API-set aliases compiled only |
| 7. Modern hardware | One documented controller/device at a time; identify PCI IDs and drivers; boot/I/O regression | No verified new hardware support |
| 8. Security/update pipeline | Native signed-manifest verifier, offline test keys, corruption/rollback tests, then TLS/trust integration | Not implemented |
| 9. VM acceleration/passthrough | Validated XP GPU driver, device reset/isolation and game regression on named hardware | Not tested |
| 10. Native AMD64/EC2 | NT 5.2 product baseline, native storage/network drivers and provider-supported deployment route | Source/platform blockers |

Kernel scheduling, memory and mitigation work must begin from measurements on a
bootable original baseline, preserving old application behavior. ASLR/NX changes
require loader, relocation and driver compatibility tests; source presence is
insufficient. Treat all current artifacts as experimental and untrusted.

For security updates, first implement a narrow native verifier with explicit key
rotation, authenticated component versions, rollback protection and transactional
recovery tests. Network download, certificate trust and driver installation come
after offline correctness. A signed manifest alone does not establish that its
payload or selected trust store is safe. No proprietary updates are redistributed.

For x64, obtain and identify an authorized NT 5.2 source/media baseline rather
than rebranding the NT 5.1 AMD64 experiments as XP Professional x64. For EC2, first
resolve the unsupported XP import route; do not substitute a Linux-hosted nested
VM wrapper for the requested native deployment.

When a native build stage is blocked, retain its diagnostic and continue with
host-side reproducibility, static dependency checks and independently compilable
native test components. Do not replace missing Microsoft core subsystems with
ReactOS to bypass a milestone gate.
