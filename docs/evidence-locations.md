# Where the `.work/` evidence lives

Milestones 7–9 were developed in separate Git worktrees, each with its own
git-ignored `.work/`. On 2026-11-22 the worktrees were consolidated:

* Every branch is contained in `xp25-nt` (pushed). `xp25-browser` was
  integrated earlier; its three AI commits appear in `xp25-nt` as same-named
  commits on a different base.
* The checkouts of `xp25-ai`, `xp25-security`, `xp25-cve`, `xp25-winlogon-ui`
  and `xp25-modernization` were removed. Each carried its own 6 GB copy of
  `Source/`, and removing them freed about 30 GB. Their branches still exist.
* Each retired directory keeps its `.work/` unchanged, together with a
  `RETIRED.md`. Libvirt domains (`XP25-AI`, `XP25-Security-8.1`,
  `XP25-Winlogon-Fix`, …) and QCOW2 backing chains use these absolute paths,
  so nothing was moved.
* `xp25-merlin` remains a worktree: the MerlinAI relay and deployment agent
  run its code, and the builder and demonstration VMs use its `.work/`.

A record's `.work/<topic>` path therefore resolves under one of these
directories, all in `/mnt/01962c02-074f-47e7-8ee3-699a169f4905/`:

| Directory | Milestone `.work/` topics (originals) |
| --- | --- |
| `winxp_2026/` (main checkout) | Milestones 1–6, native desktop, Winlogon (`winlogon-*-202610*`), branding, OneCore, toolchains, `xp-sp3-install-20261018`, `boot-debug-20261022` (also MerlinAI native builds 11 and 12), MerlinAI `merlin-dialog-ready-20261122`, `merlin-foreground-20261123` |
| `xp25-ai/` | AI components and the XP25-AI VM: `ai-20261025`, `virt-manager-XP25-AI-*`, `vm-*-20261025/26`, `oem-*`, `guacamole-remote-20261026`, `xp25-ai-gateway-20261111` |
| `xp25-security/` | Milestones 8 and 8.1: `security-20261111`, `security81-20261112`, `virt-manager-XP25-Security-81-20261112` |
| `xp25-cve/` | Milestone 8.2: `cve82-20261112` |
| `xp25-winlogon-ui/` | Account-switch fix and its VM: `winlogon-ui-20261113`, `winlogon-ui-20261116`, `winlogon-vm-20261118`, `virt-manager-XP25-Winlogon-Fix-20261118` |
| `xp25-modernization/` | Milestone 8.4, R-0, R-1, Supermium: `modernization-20261118`, `screensaver-20261119`, `r1-20261119`, `vm-redeploy-20261119`, `winlogon-vm-20261119`, `supermium-vm-20261120` |
| `xp25-merlin/` | Milestone 9: `merlin-20261121`, `merlin-builder-vm-20261121`, `merlin-demo-vm-20261121`, `merlin-vm-20261122` (XP25-Winlogon-Fix images, tests, enrollment and deployment) |

Directories such as `ai-20261025`, `security-20261111` or `cve82-20261112`
also appear in later worktrees. Those are the reflinked reference copies that
the later milestone made of the earlier frozen images; the milestone's own
record gives the exact path and hash it used.
