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
#endif
