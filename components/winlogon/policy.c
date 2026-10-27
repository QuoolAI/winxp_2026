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
static void decide(WL_POLICY_RESULT *r,WL_POLICY_DECISION decision,unsigned long error)
{r->decision=decision;r->error=error;}
void wl_policy_from_license(const WL_LICENSE_STATE *s,WL_POLICY_RESULT *r)
{
    if(!r)return;
    r->version=1;r->verified=0;decide(r,WlPolicyUnavailable,120);
    if(!s){r->error=13;return;}
    if(s->key_protected)r->verified|=WL_POLICY_KEY_PROTECTION;
    /* The agent's own failures are preserved; they never become a decision. */
    if(s->agent_error){r->error=s->agent_error;return;}
    if(s->init_status){r->error=s->init_status;return;}
    r->verified|=WL_POLICY_INITIALIZATION;
    if(s->wpa_left>WL_LICENSE_UNLIMITED||s->eval_left>WL_LICENSE_UNLIMITED){r->error=13;return;}
    if(!s->key_protected){r->error=21;return;}
    /* Same activated test as Setup and the WMI provider: WPALeft == INT_MAX.
       Zero days remaining is an expired grace or evaluation period. */
    if(!s->wpa_left||!s->eval_left){decide(r,WlPolicyDenied,5);return;}
    r->verified|=WL_POLICY_ACTIVATION;decide(r,WlPolicyAllowed,0);
}
