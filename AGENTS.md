# Windows XP 25 Anniversary Edition

Preserve the Microsoft NT kernel, Win32 subsystem, Explorer, registry, services,
Luna and application/game compatibility. This is a native Windows project.

* Treat `Source/` as the reference tree. Build in disposable copies under `.work/`.
  Do not move the supplied source layout or edit it to accommodate a host build.
* Keep patches small and reversible. Do not replace Microsoft core components
  with ReactOS, Linux or Wine components. One-Core-API may supply isolated API
  extensions and development tools; inspect their dependencies and provenance.
* NT 5.1 x86 is the identified baseline. AMD64 code/tool presence does not establish
  an XP Professional x64 / NT 5.2 baseline. Do not convert the x86 kernel to x64.
* Record executed commands, hashes, logs and exact limitations. Firmware, PE
  compilation and process presence are different evidence from an OS boot,
  functional compatibility or a completed login transition.
* Run focused tests and maintain `docs/PROGRESS.md` and `docs/COMPATIBILITY.md`.
  Keep hardware and software support unverified until tested in a recorded guest.
* Do not upload source, binaries, inventories or guest media to public CI. Do not
  push or deploy. Locally commit completed milestones using explicit project paths.
* Keep generated files, imported upstream trees and toolchains under `.work/`.
  Preserve upstream notices. Do not download or redistribute Microsoft components
  without the user's authorization and a legitimate source.
* Build hosts may use cross-compilers and QEMU. Guest components must not depend
  on a Linux, Wine, ReactOS or modern Windows runtime.

Start with the native build/boot baseline. When a stage cannot run, retain its
failure evidence and continue with an independently testable development task.
