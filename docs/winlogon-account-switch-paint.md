# Account-switching logon-control paint defect — investigation

Worktree `xp25-winlogon-ui` (branch `xp25-winlogon-ui`), from `46f8173e9`. Evidence
root `.work/winlogon-ui-20261113/` (`W`). This records the investigation into why the
logon controls sometimes fail to appear after switching users, the fix approaches
tried, and the conclusion.

## Symptom

On the first logon after boot the classic logon dialog's **User name** and
**Password** edit fields render correctly (white interior, sunken 3D border, the
`XP25` name prefilled). After a user switch (logoff → the dialog is shown again), the
dialog paints fully — title bar, Windows logo, OK/Cancel/Options buttons, the field
labels — **except the two edit fields, which render flush grey** (no white fill, no
border, no text), intermittently. Reference frames:
`xp25-security/.work/security81-20261112/runs/logon-focus-01/boot-dialog.png` (correct)
vs `logoff-dialog.png` (the two fields blank).

## A reproducible, pixel-measured harness

`vm/winlogon_switch_probe.py` boots a fresh, NIC-free overlay of the Milestone 8.1
image, optionally replaces `winlogon.exe` with a build under test, and makes a Startup
script log the `XP25` account off a few seconds after each logon so the logon dialog is
shown over and over. For each cycle it **waits until the logon dialog's beige body is on
screen** before measuring (the switch to the secure desktop first shows nothing, so a
serial marker alone is not enough — an early version keyed off the GINA's dialog marker
and sometimes captured the black gap between dialogs, scoring it as "blank", which
polluted the first measurements; the harness now confirms the dialog on screen first).
It then captures the framebuffer with a QMP `screendump` and measures the fraction of
the user-name field that is white. The reference frames calibrate the measure: the field
is **97.7 % white when painted and 0 % white when blank**, so `>= 0.6` is "painted".

With the dialog confirmed on screen every cycle, the Milestone 8.1 image's own
(unmodified) Winlogon gives a clean, deterministic signal: the logon fields paint and
fail to paint on **strictly alternating** account switches —

```
cycle 0 (boot) painted · 1 blank · 2 painted · 3 blank · 4 painted · 5 blank · 6 painted · 7 blank
```

— a period-2 toggle, not random flakiness (`base-fixed-01`). The blanks are persistent
(still blank 45 s later, `logon-focus-01/logoff-plus-45s.png`).

## What is actually wrong (measured, not inferred)

A diagnostic Winlogon build logged each edit control's state at the moment it forced a
repaint, in blank cycles:

```
edit_1502_vis_1_rect_84_112_243x20_style_50010080_ex_00000204_update_0
edit_1503_vis_1_rect_84_139_243x20_style_500100a0_ex_00000204_update_0
```

So in a blank cycle each edit is **visible** (`IsWindowVisible = 1`), correctly sized
and positioned (243×20 at 84,112 in the dialog), has `WS_EX_CLIENTEDGE` (the sunken
border), and after a forced `RedrawWindow(..., RDW_UPDATENOW)` has an **empty update
region** (`update_0`). That means win32k *did* paint the control into its surface — the
painted pixels simply never reached the QEMU VGA framebuffer that `screendump` (and a
real monitor) reads.

Two further facts pin this below the window manager:

- The failure is a clean **every-other-switch alternation** once timing stabilises
  (paint, blank, paint, blank, …), deterministic rather than random.
- In some cycles the captured image **changes over time with no Winlogon action**
  between the captures (a field blank at 2.5 s is painted at 7.5 s, or the reverse),
  i.e. the displayed framebuffer is catching up to, or diverging from, the surface on
  its own.

So the paint reaches win32k's surface but not the framebuffer, after a desktop switch.
The next section's control run shows this is driven by the Winlogon (not the display
driver): the same `framebuf.dll` paints correctly under Microsoft's Winlogon.

## Fix approaches tried, re-measured, and ruled out

All were native-built (`/W4 /WX`, clean). After the harness was corrected to confirm the
dialog on screen, each was re-measured against the clean period-2 baseline (`retest-*`):

| Approach | Where | Result (corrected harness) |
| --- | --- | --- |
| Repaint the dialog / each child (`RedrawWindow`, frame + erase, foreground), spread over ~1.5 s | `gina.c` dialog host | Leaves the alternation |
| `SWP_FRAMECHANGED` frame/clip recalculation per control | `gina.c` dialog host | Leaves the alternation |
| Full secure-desktop re-blit (`RedrawWindow(GetDesktopWindow(), …)`) | `gina.c` dialog host | Identical alternation (`retest-reblit-01`) |
| `WS_CLIPCHILDREN` on the dialog (keep the parent erase off the controls) | `gina.c` dialog host | Still alternates, shifted phase (`retest-clip-01`) |
| Lock/switch re-ordering (lock-then-switch secure, switch-then-unlock user) | `security.c` desktop switch | No change (`order-up-01`); a valid correctness/security improvement in its own right — see below |
| Drop the window-station lock entirely | `security.c` desktop switch | No change |
| Switch desktop away and back after the dialog paints | `gina.c` + desktop switch | Identical to baseline (`retest-resync-01`) |
| A persistent full-screen background window on the secure desktop | `main.c` | Identical to baseline (`retest-bg-01`) |

Every one of these leaves the strict period-2 alternation (some shift its phase). The
toggle is in the core desktop-switch/display path and survives additive repaint,
re-blit, clipping, lock and background-window changes.

(An earlier reading of these — before the harness was corrected — mistook the black gap
between dialogs for a blank field and reported a "paint then blank over time" and a
`framebuf.dll` fault. The corrected harness shows the signal is a clean, persistent
every-other-switch blank, and the control below shows it is the Winlogon.)

## The decisive control: identical display stack, only the Winlogon differs

The project's own records say "the original Winlogon paints them in the same
classic-logon test." That reference run
(`winxp_2026/.work/boot-debug-20261022/wl-original-classic-kvm-01`) booted Microsoft's
installed `winlogon.exe` on the `XP25-Components-Engineering` image, and its
`classic-after-logoff.png` shows the logon fields **painted correctly** after a logoff.

Extracting the display stack from that image and from the one these tests use:

| Binary | Components image (Microsoft winlogon, paints) | Baseline 8.1 image (XP25 winlogon, fails) |
| --- | --- | --- |
| `framebuf.dll` | `2054ab5d…` | **`2054ab5d…` — identical** |
| `win32k.sys` | `b28afb2f…` | **`b28afb2f…` — identical** |
| `gdi32.dll` | `09698075…` | **`09698075…` — identical** |
| `winlogon.exe` | `7cd68891…` (Microsoft, 509 KB) | `e3a9cdca…` (XP25, 43 KB) |

The display driver, the kernel graphics subsystem and GDI are **byte-identical**. The
only difference is `winlogon.exe`. Microsoft's Winlogon drives the same `framebuf.dll`
to paint the post-switch fields correctly; the XP25 Winlogon does not. **The defect is
in the XP25 Winlogon, not the display driver.** (An earlier draft of this document
wrongly blamed `framebuf.dll`; this control disproves that.)

## Where this leaves the fix

The defect is **in the XP25 Winlogon and is fixable there** (the identical-stack control
proves it is not the display driver), but it is a period-2 toggle in the core
desktop-switch/display path that none of the obvious levers — repaint, re-blit,
clipping, lock ordering, background window — reach. The XP25 Winlogon is 43 KB against
Microsoft's 509 KB; Microsoft's does substantially more around presenting the secure
desktop, and the specific action it takes that keeps alternate switches from blanking
has not yet been isolated. Identifying it needs either a closer reconstruction of the
classic Winlogon's secure-desktop presentation or win32k-level instrumentation of what
state toggles between a painted and a blank switch.

`vm/winlogon_switch_probe.py` is the regression oracle for that work: it reproduces the
defect on the unmodified image and scores painted-vs-blank objectively, under KVM and
TCG, so any candidate can be judged in one run.

### A separate, valid improvement found on the way

`components/winlogon/security.c` switches the secure desktop **before** locking the
window station (`wl_switch_secure` does `SwitchDesktop` then `LockWindowStation`) and
unlocks **before** switching to the user desktop. The canonical, more secure order is
the reverse — lock, then switch to the secure desktop; switch to the user desktop, then
unlock — so the station is never unlocked while the secure desktop is presented. This
does not fix the paint defect (tested), and is recorded here as a standalone follow-up.

## Evidence

`.work/winlogon-ui-20261113/`: the harness runs (`runs/control-up-02`,
`runs/*-up-0*`), each with `result.json` (per-cycle white-fraction verdicts) and the
`cycle-*-*.ppm/.png` screenshots; the native Winlogon builds (`wl-build-0*`,
`wl-collect-0*`) and build media; the frozen build VM and base image under `reference/`.
The base image (`501c7986…`) is unchanged; `Source/` is untouched.
