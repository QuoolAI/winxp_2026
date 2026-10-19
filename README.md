# Windows XP 25 Anniversary Edition

Development toward modernizing the original Microsoft Windows XP architecture
while preserving its kernel, Win32 behavior, Explorer, registry, services, Luna
and legacy software compatibility. **There is no bootable custom release yet.**

Start with [architecture](docs/architecture.md), [executed progress](docs/PROGRESS.md),
[compatibility status](docs/COMPATIBILITY.md) and [the roadmap](docs/ROADMAP.md).
Reference sources remain in `Source/XPSP1/NT`; disposable copies, toolchains,
private inventories, binaries and VM logs are kept under ignored `.work/`.

## Supplied source

This repository is leaked source code of Windows XP (NT5.1).

# Disclaimer
I do not own this source code, I just found a leak repository and forked my GitHub repository.

## Build and VM baseline

See [the baseline checkpoint and runbook](docs/build-vm-baseline.md) for the
source inventory, native build prerequisites, QEMU commands, and verified limits.
The [supplied XP SP3 guest](docs/xp-sp3-guest.md) now boots locally in KVM and
passes six native regression observations. Login and ACPI shutdown were also
observed. [Four checked source kernels now link](docs/native-kernel-build.md);
matching NTFS and checked HAL builds also succeeded. The KVM source boot
currently stops at the checked HAL APIC readback assertion before login.
Source files remain unchanged; guest disks and evidence stay private under `.work/`.

[One-Core-API analysis and reuse](docs/onecore-analysis.md) documents a pinned
upstream experiment that builds API-set forwarding DLLs on Linux for x86 and
amd64. These artifacts have passed static checks; Windows runtime testing is pending.
