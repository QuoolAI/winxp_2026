/* Explicit doubles, linked only into the separate test executable. */
#ifndef XP25_SESSION_TEST
#error This file is only for the separate session test target
#endif
#include <stdio.h>
#include <string.h>
#include "session_engine.h"
static unsigned checks,failures,cases;
static void check(int condition,unsigned line)
{++checks;if(!condition){++failures;printf("FAIL line %u\n",line);}}
#define CHECK(c) check(!!(c),(unsigned)__LINE__)
typedef struct {
    WL_MACHINE machine;WL_SESSION_ENGINE engine;
    WL_POLICY_RESULT policy;
    WL_SESSION_OPERATION fault;
    int notification_fault;
    unsigned token,profile,host_env,copy_alive,copy_taken,process,secure,protected_objects;
    unsigned copies,copy_frees,host_frees,profiles_freed,tokens_closed,activations,ends,policies;
    unsigned calls[20],notices[7];
    char copy[4],host[4];
} FIXTURE;
static unsigned long tick(FIXTURE *f,WL_SESSION_OPERATION op)
{++f->calls[op];return f->fault==op?1234:0;}
static unsigned long user(void *p)
{FIXTURE *f=p;unsigned long e=tick(f,WlOpUser);return !f->token?5:e;}
static unsigned long profile(void *p)
{FIXTURE *f=p;f->profile=f->host_env=1;return tick(f,WlOpProfile);}
static void policy(void *p,WL_POLICY_RESULT *r)
{FIXTURE *f=p;++f->policies;*r=f->policy;}
static unsigned long copy_env(void *p,void **out)
{FIXTURE *f=p;CHECK(f->host_env);++f->copies;f->copy_alive=1;*out=f->copy;return tick(f,WlOpCopyEnvironment);}
static unsigned long discard(void *p,void *copy)
{FIXTURE *f=p;CHECK(copy==f->copy);CHECK(f->copy_alive&&!f->copy_taken);f->copy_alive=0;++f->copy_frees;return 0;}
static unsigned long secure(void *p)
{FIXTURE *f=p;f->secure=1;return tick(f,WlOpSecure);}
static unsigned long protect(void *p)
{FIXTURE *f=p;CHECK(f->secure&&f->token);f->protected_objects=1;return tick(f,WlOpProtection);}
static unsigned long activate(void *p,void *copy)
{
    FIXTURE *f=p;CHECK(copy==f->copy&&copy!=(void*)f->host);
    CHECK(f->secure&&f->token&&f->profile&&f->copy_alive&&f->protected_objects);
    CHECK(f->engine.environment_copy==0);f->copy_taken=1;f->process=1;++f->activations;
    return tick(f,WlOpActivate);
}
static unsigned long identity(void *p)
{FIXTURE *f=p;CHECK(f->process&&f->token);return tick(f,WlOpShellIdentity);}
static unsigned long desktop(void *p)
{FIXTURE *f=p;CHECK(f->process&&f->token);f->secure=0;return tick(f,WlOpDesktop);}
static unsigned long notify(void *p,WL_SESSION_NOTICE event)
{FIXTURE *f=p;++f->notices[event];return f->notification_fault==(int)event?9876:0;}
static unsigned long end_processes(void *p)
{
    FIXTURE *f=p;unsigned long e=tick(f,WlOpEndProcesses);++f->ends;CHECK(f->secure&&f->token);
    if(e)return e;
    f->process=0;f->protected_objects=0;return 0;
}
static unsigned long release(void *p)
{
    FIXTURE *f=p;unsigned long e=tick(f,WlOpRelease);CHECK(!f->process);CHECK(f->secure);
    if(e)return e;
    if(f->copy_alive){CHECK(f->copy_taken);f->copy_alive=0;++f->copy_frees;}
    if(f->host_env){f->host_env=0;++f->host_frees;}
    if(f->profile){f->profile=0;++f->profiles_freed;}
    if(f->token){f->token=0;++f->tokens_closed;}return 0;
}
static unsigned long power(void *p,unsigned mode)
{FIXTURE *f=p;CHECK(mode<=1);CHECK(!f->token&&!f->profile&&!f->process);return tick(f,WlOpPower);}
static const WL_SESSION_DRIVER doubles={user,profile,policy,copy_env,discard,secure,protect,activate,identity,desktop,notify,end_processes,release,power};
static void fixture(FIXTURE *f)
{
    memset(f,0,sizeof(*f));f->token=1;f->secure=1;f->notification_fault=-1;
    f->policy.version=1;f->policy.decision=WlPolicyAllowed;f->policy.verified=WL_POLICY_REQUIRED;
    wl_state_init(&f->machine);
    CHECK(wl_state_step(&f->machine,WlBootReady,WL_BOOT_FACTS));
    CHECK(wl_state_step(&f->machine,WlAttention,WL_SECURE_ACTIVE));
    CHECK(wl_state_step(&f->machine,WlAuthenticated,WL_TOKEN_CHECKED));
    wl_engine_bind(&f->engine,&f->machine,&doubles,f);
}
static void gone(FIXTURE *f)
{
    CHECK(!f->token&&!f->profile&&!f->host_env&&!f->copy_alive&&!f->process);
    CHECK(f->machine.phase==WlSignedOut&&!f->machine.token_owned&&!f->machine.profile_owned&&!f->machine.shell_owned);
    CHECK(f->copies==f->copy_frees);CHECK(f->tokens_closed==1);
}
int wl_session_tests(void)
{
    FIXTURE f;WL_SESSION_OPERATION faults[]={WlOpUser,WlOpProfile,WlOpCopyEnvironment,WlOpSecure,
        WlOpProtection,WlOpActivate,WlOpShellIdentity,WlOpDesktop};
    unsigned i,mask;WL_POLICY_RESULT r;WL_MACHINE before;
    checks=failures=cases=0;
    /* All policy combinations, including a nominal allow without evidence. */
    for(mask=0;mask<8;++mask){
        ++cases;fixture(&f);f.policy.verified=mask;
        if(mask==WL_POLICY_REQUIRED){CHECK(wl_engine_start(&f.engine));CHECK(wl_engine_logoff(&f.engine));}
        else{CHECK(!wl_engine_start(&f.engine));CHECK(f.engine.operation==WlOpPolicy);CHECK(!f.activations&&!f.copies);CHECK(wl_engine_abort(&f.engine));}
        gone(&f);
    }
    ++cases;fixture(&f);f.policy.decision=WlPolicyDenied;f.policy.error=775;
    CHECK(!wl_engine_start(&f.engine)&&f.engine.error==775);CHECK(wl_engine_abort(&f.engine));gone(&f);
    ++cases;fixture(&f);f.policy.decision=WlPolicyUnavailable;
    CHECK(!wl_engine_start(&f.engine)&&f.engine.error==120);CHECK(!f.activations);CHECK(wl_engine_abort(&f.engine));gone(&f);
    ++cases;fixture(&f);f.token=0;CHECK(!wl_engine_start(&f.engine));CHECK(f.engine.error==5);
    CHECK(!f.policies&&!f.calls[WlOpProfile]&&!f.activations);f.token=1;CHECK(wl_engine_abort(&f.engine));gone(&f);
    for(i=0;i<sizeof(faults)/sizeof(faults[0]);++i){
        ++cases;fixture(&f);f.fault=faults[i];CHECK(!wl_engine_start(&f.engine));CHECK(f.engine.error==1234);
        if(f.fault==WlOpDesktop)CHECK(f.secure);
        f.fault=WlOpNone;CHECK(wl_engine_abort(&f.engine));gone(&f);
        CHECK(!wl_engine_abort(&f.engine));CHECK(f.tokens_closed==1);
    }
    for(i=0;i<3;++i){
        ++cases;fixture(&f);f.notification_fault=(int)i;
        CHECK(!wl_engine_start(&f.engine)&&f.engine.error==9876);f.notification_fault=-1;
        CHECK(wl_engine_abort(&f.engine));gone(&f);
    }
    ++cases;fixture(&f);CHECK(wl_engine_start(&f.engine));
    CHECK(f.machine.phase==WlInteractive&&f.machine.token_owned&&f.machine.profile_owned&&f.machine.shell_owned);
    CHECK(f.activations==1&&f.copy_alive&&f.host_env&&!f.secure);
    CHECK(f.notices[WlNoticeLogon]==1&&f.notices[WlNoticeStartShell]==1&&f.notices[WlNoticePostShell]==1);
    CHECK(wl_engine_lock(&f.engine));CHECK(f.machine.phase==WlLocked&&f.secure);
    CHECK(wl_state_step(&f.machine,WlAttention,WL_SECURE_ACTIVE));before=f.machine;
    CHECK(!wl_engine_unlock(&f.engine,0));CHECK(!memcmp(&before,&f.machine,sizeof(before)));
    CHECK(wl_engine_unlock(&f.engine,1));CHECK(f.machine.phase==WlInteractive&&!f.secure);
    CHECK(f.notices[WlNoticeLock]==1&&f.notices[WlNoticeUnlock]==1);
    CHECK(wl_engine_logoff(&f.engine));gone(&f);CHECK(f.machine.generation==1);
    CHECK(f.notices[WlNoticeLogoff]==1&&f.ends==1);
    CHECK(wl_engine_power(&f.engine,1));CHECK(f.machine.phase==WlPowerDown&&f.notices[WlNoticeShutdown]==1);
    /* Failures must retain the token and profile if cleanup cannot complete. */
    ++cases;fixture(&f);f.fault=WlOpActivate;CHECK(!wl_engine_start(&f.engine));f.fault=WlOpEndProcesses;
    CHECK(!wl_engine_abort(&f.engine));CHECK(f.machine.phase==WlFailed&&f.token&&f.profile&&f.copy_alive);
    CHECK(!f.tokens_closed&&!f.profiles_freed);
    ++cases;fixture(&f);f.policy.decision=WlPolicyDenied;CHECK(!wl_engine_start(&f.engine));f.fault=WlOpRelease;
    CHECK(!wl_engine_abort(&f.engine));CHECK(f.machine.phase==WlFailed&&f.token&&f.profile);
    ++cases;fixture(&f);CHECK(wl_engine_start(&f.engine));f.fault=WlOpEndProcesses;
    CHECK(!wl_engine_logoff(&f.engine));CHECK(f.machine.phase==WlFailed&&f.token&&f.profile);
    ++cases;fixture(&f);CHECK(wl_engine_start(&f.engine));CHECK(wl_engine_lock(&f.engine));
    CHECK(wl_state_step(&f.machine,WlAttention,WL_SECURE_ACTIVE));f.fault=WlOpDesktop;
    CHECK(!wl_engine_unlock(&f.engine,1));CHECK(f.machine.phase==WlLocked&&f.secure);
    f.fault=WlOpNone;CHECK(wl_engine_logoff(&f.engine));gone(&f);
    for(i=0;i<2;++i){
        ++cases;fixture(&f);CHECK(!wl_engine_power(&f.engine,i));CHECK(wl_engine_start(&f.engine));
        CHECK(wl_engine_logoff(&f.engine));f.fault=WlOpPower;CHECK(!wl_engine_power(&f.engine,i));
        CHECK(f.machine.phase==WlSignedOut);f.fault=WlOpNone;CHECK(wl_engine_power(&f.engine,i));
    }
    ++cases;fixture(&f);CHECK(wl_engine_start(&f.engine));CHECK(wl_engine_logoff(&f.engine));
    f.token=1;CHECK(wl_state_step(&f.machine,WlAttention,WL_SECURE_ACTIVE));
    CHECK(wl_state_step(&f.machine,WlAuthenticated,WL_TOKEN_CHECKED));
    wl_engine_bind(&f.engine,&f.machine,&doubles,&f);CHECK(wl_engine_start(&f.engine));
    CHECK(wl_engine_logoff(&f.engine));CHECK(f.machine.generation==2&&f.tokens_closed==2&&f.copy_frees==2);
    ++cases;memset(&r,0,sizeof(r));CHECK(wl_policy_admission(&r)==13);CHECK(wl_policy_admission(0)==13);
    r.version=1;r.decision=(WL_POLICY_DECISION)99;CHECK(wl_policy_admission(&r)==13);
    r.decision=WlPolicyAllowed;r.verified=WL_POLICY_REQUIRED;r.error=55;CHECK(wl_policy_admission(&r)==55);
    printf("XP25_SESSION_TEST_ONLY cases=%u checks=%u failures=%u\n",cases,checks,failures);
    return failures?1:0;
}
#ifndef XP25_NATIVE_TEST_ENTRY
int main(void){return wl_session_tests();}
#endif
