/* Original XP25 policy contract. An observation is not permission to log on. */
#ifndef XP25_POLICY_H
#define XP25_POLICY_H
#if defined(XP25_PRODUCTION_WINLOGON) && defined(XP25_SESSION_TEST)
#error Test session drivers cannot be compiled into production Winlogon
#endif
typedef enum { WlPolicyUnavailable, WlPolicyDenied, WlPolicyAllowed } WL_POLICY_DECISION;
#define WL_POLICY_ACTIVATION       1u
#define WL_POLICY_KEY_PROTECTION   2u
#define WL_POLICY_INITIALIZATION  4u
#define WL_POLICY_REQUIRED (WL_POLICY_ACTIVATION|WL_POLICY_KEY_PROTECTION|WL_POLICY_INITIALIZATION)
typedef struct {
    unsigned version;
    WL_POLICY_DECISION decision;
    unsigned verified;
    unsigned long error;
} WL_POLICY_RESULT;
/* Returns a Win32 error (0 only for a complete, explicit allow decision). */
unsigned long wl_policy_admission(const WL_POLICY_RESULT *result);

/* Outputs of the supplied licensing agent (licdll COMLicenseAgent), recorded
   exactly as returned. Only the native provider fills this; nothing here is
   inferred from registry data, WMI or a GINA result. */
#define WL_LICENSE_UNLIMITED 0x7fffffffUL
typedef struct {
    unsigned key_protected;     /* NtLockProductActivationKeys succeeded */
    unsigned long agent_error;  /* Win32 error creating/verifying/calling the agent */
    unsigned long init_status;  /* ICOMLicenseAgent::Initialize pdwRetCode */
    unsigned long wpa_left;     /* GetExpirationInfo: activation grace days, or unlimited */
    unsigned long eval_left;    /* GetExpirationInfo: evaluation days, or unlimited */
} WL_LICENSE_STATE;
/* Activated or within the grace/evaluation period: allowed. An expired grace or
   evaluation period: denied. Any agent failure or malformed output: unavailable. */
void wl_policy_from_license(const WL_LICENSE_STATE *state,WL_POLICY_RESULT *result);
#endif
