#include "policy.h"
unsigned long wl_policy_admission(const WL_POLICY_RESULT *r)
{
    if(!r||r->version!=1)return 13;
    if(r->decision==WlPolicyDenied)return r->error?r->error:5;
    if(r->decision==WlPolicyUnavailable)return r->error?r->error:120;
    if(r->decision!=WlPolicyAllowed)return 13;
    if(r->error)return r->error;
    if((r->verified&WL_POLICY_REQUIRED)!=WL_POLICY_REQUIRED)return 120;
    return 0;
}
