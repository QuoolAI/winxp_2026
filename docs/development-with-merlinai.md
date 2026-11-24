# Developing XP25 now that MerlinAI builds updates

Two loops now change XP25:

| | Engineering loop (Claude Code, Codex, people) | Repair loop (MerlinAI) |
| --- | --- | --- |
| Input | A goal or defect, the repository | A problem an enrolled VM observed itself |
| Works on | Source in this repository: `components/`, `build/`, `vm/`, patches | One job: a change made inside the builder VM on a copy of the tools and the reference source |
| Proves with | Host tests, native builds in disposable build VMs, lab runs on frozen images, docs | Control build reproduces the installed binary; the candidate differs only by the change; nested tests (UP, MP, TCG) |
| Produces | Commits; packaged images and components | A binary delta for one installation's baseline, applied only after the user approves it in the VM, with Roll Back |
| Source of truth | Git (`master`) | The job record on the builder |

The two loops use different mechanisms, so they do not get in each other's way while building. They conflict in
two places:

1. **A MerlinAI fix exists only as a delta.** The FltMgr repair added `RtlAddAccessAllowedAceEx` to the kernel's
   export list inside the builder job. The repository's kernel export list does not have it yet. The next kernel
   built from the repository would drop the fix.
2. **Deploying to the same VM.** The deployment agent applies updates only on top of the revision it recorded
   (`/xp25/image-revision.txt` gates every update). The builder builds against a baseline image. A disk swapped or
   packaged outside the agent leaves both stale, and later MerlinAI updates are refused or built for the wrong
   system.

## Rules

* **Git is the source of truth.** Every MerlinAI job that is applied is upstreamed as an ordinary commit: its
  change, a host test where one is possible, and the job's provenance recorded in the docs. A Claude Code or Codex
  session does this from the job record (`builder-job-<id>.json`, the builder's job directory).
* **Enrolled VMs change only through the deployment agent.** That includes XP25-Winlogon-Fix. No more disk swaps
  or offline replacement on them. A change from the engineering loop reaches them in one of two ways:
  * as a new builder baseline plus a revision, for a whole image (`builder_vm.py add-baseline`, then the agent);
  * as a MerlinAI job built from the merged source, for a component.

  Either way, Apply and Roll Back keep working.
* **The builder builds what `master` says.** When recipes, tools or XP25 sources change, refresh the builder's
  tools snapshot from `master`. Otherwise MerlinAI keeps building with old recipes.
* **The engineering loop owns what MerlinAI cannot do:**
  * new features;
  * Microsoft components that are not wired as recipes yet (22 of them);
  * binary-only components;
  * third-party software failures;
  * reviewing whatever MerlinAI's model proposes before it is upstreamed.
* **Codex and Claude Code** work in the same checkout. They should not edit the same branch at the same time: use
  separate branches or worktrees, commit locally, and merge to `master` one at a time.
* **Newbie template.** After an update is applied to XP25-Winlogon-Fix, rebuild the Mise En Abyme Newbie template
  from the same baseline and update ([mea-xp25-desktops.md](mea-xp25-desktops.md)).

## Open item from this rule

The FltMgr export (`RtlAddAccessAllowedAceEx`) is applied on XP25-Winlogon-Fix but not yet in the repository's
kernel export list. It should be upstreamed before the next kernel build.
