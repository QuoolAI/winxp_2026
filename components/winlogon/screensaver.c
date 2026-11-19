/* XP25 original screen-saver decision rules. A secure saver exists only in a logged-on
   session; at the logon desktop and on a locked station nothing remains to protect, and
   no application there can decline the saver, so either start notice starts it. */
#include "screensaver.h"

WL_SAVER_PLACE wl_saver_place(WL_PHASE phase)
{
    switch (phase) {
    case WlSignedOut: case WlAuthenticating: return WlSaverLogonDesktop;
    case WlInteractive: return WlSaverSession;
    /* Without Ctrl+Alt+Del MSGINA shows its unlock dialog at once, with no timeout. */
    case WlLocked: case WlUnlocking: return WlSaverLocked;
    default: return WlSaverNowhere;
    }
}

int wl_saver_consult(WL_SAVER_PLACE place, unsigned request, const WL_SAVER_SETTINGS *s, unsigned *secure)
{
    if (!secure) return 0;
    *secure = 0;
    if (place == WlSaverNowhere || !s || request > WL_SAVER_REQUEST_MONITOR_OFF) return 0;
    if (request == WL_SAVER_REQUEST_MONITOR_OFF) {
        /* Nothing is shown on a dark screen; a secure session saver locks at once. */
        if (place != WlSaverSession || !s->active || !s->secure) return 0;
        *secure = 1;
        return 1;
    }
    if (!s->active || !s->image) return 0;
    if (place == WlSaverSession) *secure = s->secure ? 1u : 0u;
    if (request == WL_SAVER_REQUEST_SECURE_ONLY && place == WlSaverSession && !*secure) return 0;
    return 1;
}

WL_SAVER_ACTION wl_saver_decide(WL_SAVER_PLACE place, unsigned request, int gina_allows, unsigned secure)
{
    if (place == WlSaverNowhere || request > WL_SAVER_REQUEST_MONITOR_OFF || !gina_allows) return WlSaverIgnore;
    if (place != WlSaverSession) secure = 0;
    if (request == WL_SAVER_REQUEST_MONITOR_OFF) return secure ? WlSaverLockNow : WlSaverIgnore;
    if (request == WL_SAVER_REQUEST_SECURE_ONLY && place == WlSaverSession && !secure) return WlSaverIgnore;
    return WlSaverStart;
}

WL_SAVER_RETURN wl_saver_return(WL_SAVER_PLACE place, unsigned secure)
{
    if (place == WlSaverSession) return secure ? WlSaverLockSession : WlSaverBackToDesktop;
    if (place == WlSaverLocked) return WlSaverBackToLocked;
    return WlSaverBackToLogon;
}
