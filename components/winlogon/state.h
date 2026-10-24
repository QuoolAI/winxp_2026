/* XP25 original implementation. No credentials or OS handles enter this model. */
#ifndef XP25_WINLOGON_STATE_H
#define XP25_WINLOGON_STATE_H

typedef enum {
    WlBootstrap, WlSignedOut, WlAuthenticating, WlLoadingProfile,
    WlStartingShell, WlInteractive, WlSecurityOptions, WlLocked,
    WlUnlocking, WlLoggingOff, WlPowerDown, WlFailed
} WL_PHASE;

typedef enum {
    WlBootReady, WlAttention, WlAuthenticated, WlDenied, WlCancelled,
    WlProfileReady, WlShellReady, WlLockCompleted, WlUnlockCompleted,
    WlLogoffRequested, WlSessionReleased, WlPowerRequested,
    WlRollbackCompleted, WlFatalError
} WL_EVENT;

/* Facts are supplied only after the corresponding native operation succeeds.
   They are never inferred from a GINA action code or an external window message. */
#define WL_READY_USER       0x0001u
#define WL_READY_LSA        0x0002u
#define WL_READY_DESKTOP    0x0004u
#define WL_READY_GINA       0x0008u
#define WL_TOKEN_CHECKED    0x0010u
#define WL_PROFILE_LOADED   0x0020u
#define WL_SHELL_USER       0x0040u
#define WL_SECURE_ACTIVE    0x0080u
#define WL_UNLOCK_CHECKED   0x0100u
#define WL_USER_ACTIVE      0x0200u
#define WL_RESOURCES_GONE   0x0400u
#define WL_BOOT_FACTS (WL_READY_USER|WL_READY_LSA|WL_READY_DESKTOP|WL_READY_GINA|WL_SECURE_ACTIVE)

typedef struct {
    WL_PHASE phase;
    unsigned long generation;
    unsigned int token_owned;
    unsigned int profile_owned;
    unsigned int shell_owned;
} WL_MACHINE;

void wl_state_init(WL_MACHINE *machine);
int wl_state_step(WL_MACHINE *machine, WL_EVENT event, unsigned int facts);
const char *wl_phase_name(WL_PHASE phase);
#endif
