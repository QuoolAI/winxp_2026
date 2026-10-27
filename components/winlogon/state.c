/* XP25 original state reducer, derived from the documented WLX interaction
   contract. A rejected event leaves all ownership and state unchanged. */
#include "state.h"

static int ownership_valid(const WL_MACHINE *m)
{
    switch (m->phase) {
    case WlBootstrap: case WlSignedOut: case WlAuthenticating: case WlPowerDown:
        return !m->token_owned && !m->profile_owned && !m->shell_owned;
    case WlLoadingProfile:
        return m->token_owned && !m->profile_owned && !m->shell_owned;
    case WlStartingShell:
        return m->token_owned && m->profile_owned && !m->shell_owned;
    case WlInteractive: case WlSecurityOptions: case WlLocked: case WlUnlocking: case WlLoggingOff:
        return m->token_owned && m->profile_owned && m->shell_owned;
    case WlFailed:
        return 1; /* Failed cleanup must not forget still-owned resources. */
    default:
        return 0;
    }
}

void wl_state_init(WL_MACHINE *m)
{
    m->phase = WlBootstrap;
    m->generation = 0;
    m->token_owned = m->profile_owned = m->shell_owned = 0;
}

int wl_state_step(WL_MACHINE *m, WL_EVENT event, unsigned int facts)
{
    WL_MACHINE next = *m;
    if (!ownership_valid(m)) return 0;
    switch (event) {
    case WlBootReady:
        if (m->phase != WlBootstrap || (facts & WL_BOOT_FACTS) != WL_BOOT_FACTS) return 0;
        next.phase = WlSignedOut;
        break;
    case WlAttention:
        if (m->phase == WlSignedOut) next.phase = WlAuthenticating;
        else if (m->phase == WlInteractive) next.phase = WlSecurityOptions;
        else if (m->phase == WlLocked) next.phase = WlUnlocking;
        else return 0; /* Do not reenter a GINA authentication callback. */
        if (!(facts & WL_SECURE_ACTIVE)) return 0;
        break;
    case WlAuthenticated:
        if (m->phase != WlAuthenticating || !(facts & WL_TOKEN_CHECKED)) return 0;
        next.token_owned = 1;
        next.phase = WlLoadingProfile;
        break;
    case WlDenied:
    case WlCancelled:
        if (m->phase == WlAuthenticating) next.phase = WlSignedOut;
        else if (m->phase == WlUnlocking) next.phase = WlLocked;
        else if (m->phase == WlSecurityOptions && (facts & WL_USER_ACTIVE)) next.phase = WlInteractive;
        else return 0;
        break;
    case WlProfileReady:
        if (m->phase != WlLoadingProfile || !m->token_owned || !(facts & WL_PROFILE_LOADED)) return 0;
        next.profile_owned = 1;
        next.phase = WlStartingShell;
        break;
    case WlShellReady:
        if (m->phase != WlStartingShell || !m->token_owned || !m->profile_owned ||
            (facts & (WL_SHELL_USER|WL_USER_ACTIVE)) != (WL_SHELL_USER|WL_USER_ACTIVE)) return 0;
        next.shell_owned = 1;
        next.phase = WlInteractive;
        break;
    case WlLockCompleted:
        if ((m->phase != WlInteractive && m->phase != WlSecurityOptions) || !(facts & WL_SECURE_ACTIVE)) return 0;
        next.phase = WlLocked;
        break;
    case WlUnlockCompleted:
        if (m->phase != WlUnlocking ||
            (facts & (WL_UNLOCK_CHECKED|WL_USER_ACTIVE)) != (WL_UNLOCK_CHECKED|WL_USER_ACTIVE)) return 0;
        next.phase = WlInteractive;
        break;
    case WlLogoffRequested:
        if ((m->phase != WlInteractive && m->phase != WlSecurityOptions &&
             m->phase != WlLocked && m->phase != WlUnlocking) || !(facts & WL_SECURE_ACTIVE)) return 0;
        next.phase = WlLoggingOff;
        break;
    case WlSessionReleased:
        if (m->phase != WlLoggingOff || !(facts & WL_RESOURCES_GONE) || !(facts & WL_SECURE_ACTIVE)) return 0;
        next.token_owned = next.profile_owned = next.shell_owned = 0;
        ++next.generation;
        next.phase = WlSignedOut;
        break;
    case WlPowerRequested:
        if (m->phase != WlSignedOut || m->token_owned || m->profile_owned || m->shell_owned ||
            !(facts & WL_SECURE_ACTIVE)) return 0;
        next.phase = WlPowerDown;
        break;
    case WlRollbackCompleted:
        if ((m->phase != WlLoadingProfile && m->phase != WlStartingShell) ||
            (facts & (WL_RESOURCES_GONE|WL_SECURE_ACTIVE)) != (WL_RESOURCES_GONE|WL_SECURE_ACTIVE)) return 0;
        next.token_owned = next.profile_owned = next.shell_owned = 0;
        next.phase = WlSignedOut;
        break;
    case WlFatalError:
        next.phase = WlFailed;
        break;
    default:
        return 0;
    }
    *m = next;
    return 1;
}

const char *wl_phase_name(WL_PHASE phase)
{
    static const char *names[] = {"bootstrap", "signed-out", "authenticating", "loading-profile",
        "starting-shell", "interactive", "security-options", "locked", "unlocking",
        "logging-off", "power-down", "failed"};
    return (unsigned int)phase < sizeof(names)/sizeof(names[0]) ? names[phase] : "invalid";
}
