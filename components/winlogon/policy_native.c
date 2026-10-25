#include "platform.h"
static BOOL key_protection_initialized;

BOOL wl_policy_initialize(void)
{
    LONG (NTAPI *lock_keys)(PULONG,PULONG);LONG status;ULONG a=0,b=0;
    /* @8 ABI, two output pointers and successful original calls are retained
       in the policy-control trace. This calls the supplied real kernel code;
       neither output is interpreted as an activation/entitlement decision. */
    if(key_protection_initialized)return TRUE;
    lock_keys=(LONG(NTAPI*)(PULONG,PULONG))GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtLockProductActivationKeys");
    if(!lock_keys){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    status=lock_keys(&a,&b);wl_log("product_key_protection_ntstatus",(DWORD)status);
    if(status<0){SetLastError(LsaNtStatusToWinError(status));return FALSE;}
    key_protection_initialized=TRUE;
    wl_log("product_key_protection_output_a",a);wl_log("product_key_protection_output_b",b);return TRUE;
}

void wl_session_policy(WL_POLICY_RESULT *result)
{
    ZeroMemory(result,sizeof(*result));result->version=1;
    /* Real NtLockProductActivationKeys exists in the supplied systime.obj.
       Its existence and an activation-status observation do not establish the
       original Winlogon initialization/decision contract. No success is inferred. */
    result->decision=WlPolicyUnavailable;result->error=ERROR_CALL_NOT_IMPLEMENTED;
    if(key_protection_initialized)result->verified=WL_POLICY_KEY_PROTECTION;
    wl_log("activation_policy_contract_unresolved",result->error);
}
