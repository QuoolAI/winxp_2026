/* XP25 original screen-saver decisions for USER's LOGON_INPUT_TIMEOUT notice and the
   WLX 1.1 WlxScreenSaverNotify contract. Portable C89: no handles, paths or registry text. */
#ifndef XP25_WINLOGON_SCREENSAVER_H
#define XP25_WINLOGON_SCREENSAVER_H
#include "state.h"

/* The notice's argument, from win32k StartScreenSaver: start; start only if the saver is
   secure (the foreground application may still decline through SC_SCREENSAVE, which then
   sends a plain start); the monitor is powered off. */
#define WL_SAVER_REQUEST_START       0u
#define WL_SAVER_REQUEST_SECURE_ONLY 1u
#define WL_SAVER_REQUEST_MONITOR_OFF 2u

typedef enum { WlSaverNowhere, WlSaverLogonDesktop, WlSaverSession, WlSaverLocked } WL_SAVER_PLACE;
typedef enum { WlSaverIgnore, WlSaverStart, WlSaverLockNow } WL_SAVER_ACTION;
typedef enum { WlSaverBackToLogon, WlSaverBackToDesktop, WlSaverLockSession, WlSaverBackToLocked } WL_SAVER_RETURN;

typedef struct {
    unsigned active;    /* ScreenSaveActive, policy applied */
    unsigned image;     /* SCRNSAVE.EXE names an existing local file */
    unsigned secure;    /* ScreenSaverIsSecure, policy applied */
} WL_SAVER_SETTINGS;

/* Where a saver may run in this phase. Transitions and the security-options dialog (it
   has its own timeout) are Nowhere; the unlock dialog counts as the locked station. */
WL_SAVER_PLACE wl_saver_place(WL_PHASE phase);
/* Whether the request can start anything with these settings, so the GINA is asked, and
   the secure flag to offer it. Only a session saver can be secure. */
int wl_saver_consult(WL_SAVER_PLACE place, unsigned request, const WL_SAVER_SETTINGS *settings, unsigned *secure);
/* The final decision after the GINA's answer (allowed, possibly changed secure flag). */
WL_SAVER_ACTION wl_saver_decide(WL_SAVER_PLACE place, unsigned request, int gina_allows, unsigned secure);
/* What follows the saver's exit. A secure session saver always ends in a lock. */
WL_SAVER_RETURN wl_saver_return(WL_SAVER_PLACE place, unsigned secure);
#endif
