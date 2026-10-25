#include "session_engine.h"

static int failed(WL_SESSION_ENGINE *e,WL_SESSION_OPERATION op,unsigned long error)
{e->operation=op;e->error=error?error:13;return 0;}
static int valid(WL_SESSION_ENGINE *e)
{
    const WL_SESSION_DRIVER *d;
    if(!e||!e->machine)return 0;
    d=e->driver;if(!d)return 0;
    return d->user&&d->profile&&d->policy&&d->copy_environment&&d->discard_environment&&
        d->secure&&d->protect&&d->activate&&d->shell_identity&&d->desktop&&d->notify&&
        d->end_processes&&d->release&&d->power;
}
static int call(WL_SESSION_ENGINE *e,WL_SESSION_OPERATION op,unsigned long error)
{return error?failed(e,op,error):1;}
static int notice(WL_SESSION_ENGINE *e,WL_SESSION_NOTICE n)
{return call(e,WlOpNotification,e->driver->notify(e->context,n));}
static int state(WL_SESSION_ENGINE *e,WL_EVENT event,unsigned facts)
{return wl_state_step(e->machine,event,facts)?1:failed(e,WlOpState,13);}
static int policy(WL_SESSION_ENGINE *e)
{
    WL_POLICY_RESULT r={0,WlPolicyUnavailable,0,0};
    e->driver->policy(e->context,&r);e->policy_result=r;
    return call(e,WlOpPolicy,wl_policy_admission(&r));
}
void wl_engine_bind(WL_SESSION_ENGINE *e,WL_MACHINE *m,const WL_SESSION_DRIVER *d,void *context)
{
    e->machine=m;e->driver=d;e->context=context;e->environment_copy=0;
    e->protection_attempted=e->shell_attempted=0;e->error=0;e->operation=WlOpNone;
    e->policy_result.version=0;e->policy_result.decision=WlPolicyUnavailable;
    e->policy_result.verified=0;e->policy_result.error=0;
}
int wl_engine_start(WL_SESSION_ENGINE *e)
{
    void *copy;unsigned long error;
    if(!valid(e))return e?failed(e,WlOpState,13):0;
    if(e->machine->phase!=WlLoadingProfile||!e->machine->token_owned||
       e->environment_copy||e->protection_attempted||e->shell_attempted)return failed(e,WlOpState,13);
    e->error=0;e->operation=WlOpNone;
    if(!call(e,WlOpUser,e->driver->user(e->context)))return 0;
    if(!call(e,WlOpProfile,e->driver->profile(e->context)))return 0;
    if(!state(e,WlProfileReady,WL_PROFILE_LOADED)||!policy(e))return 0;
    if(!call(e,WlOpCopyEnvironment,e->driver->copy_environment(e->context,&e->environment_copy)))return 0;
    if(!e->environment_copy)return failed(e,WlOpCopyEnvironment,13);
    if(!call(e,WlOpSecure,e->driver->secure(e->context)))return 0;
    e->protection_attempted=1;
    if(!call(e,WlOpProtection,e->driver->protect(e->context)))return 0;
    if(!notice(e,WlNoticeLogon)||!notice(e,WlNoticeStartShell))return 0;
    copy=e->environment_copy;e->environment_copy=0;e->shell_attempted=1;
    error=e->driver->activate(e->context,copy);
    if(!call(e,WlOpActivate,error))return 0;
    if(!call(e,WlOpShellIdentity,e->driver->shell_identity(e->context)))return 0;
    if(!notice(e,WlNoticePostShell))return 0;
    error=e->driver->desktop(e->context);
    if(error){
        if(!call(e,WlOpSecure,e->driver->secure(e->context)))return 0;
        return failed(e,WlOpDesktop,error);
    }
    return state(e,WlShellReady,WL_SHELL_USER|WL_USER_ACTIVE);
}
int wl_engine_abort(WL_SESSION_ENGINE *e)
{
    if(!valid(e))return 0;
    if(e->machine->phase!=WlLoadingProfile&&e->machine->phase!=WlStartingShell)return failed(e,WlOpState,13);
    if(!call(e,WlOpSecure,e->driver->secure(e->context)))goto fatal;
    if(e->environment_copy){
        if(!call(e,WlOpRelease,e->driver->discard_environment(e->context,e->environment_copy)))goto fatal;
        e->environment_copy=0;
    }
    /* The adapter must also revoke any partially assigned desktop grants. */
    if((e->shell_attempted||e->protection_attempted)&&
       !call(e,WlOpEndProcesses,e->driver->end_processes(e->context)))goto fatal;
    if(!call(e,WlOpRelease,e->driver->release(e->context)))goto fatal;
    if(!state(e,WlRollbackCompleted,WL_SECURE_ACTIVE|WL_RESOURCES_GONE))goto fatal;
    e->protection_attempted=e->shell_attempted=0;return 1;
fatal:
    wl_state_step(e->machine,WlFatalError,0);return 0;
}
int wl_engine_lock(WL_SESSION_ENGINE *e)
{
    if(!valid(e))return 0;
    if(e->machine->phase!=WlInteractive&&e->machine->phase!=WlSecurityOptions)return failed(e,WlOpState,13);
    if(!call(e,WlOpUser,e->driver->user(e->context))||
       !call(e,WlOpSecure,e->driver->secure(e->context))||
       !state(e,WlLockCompleted,WL_SECURE_ACTIVE))return 0;
    return notice(e,WlNoticeLock);
}
int wl_engine_unlock(WL_SESSION_ENGINE *e,int authenticated)
{
    unsigned long error;
    if(!valid(e))return 0;
    if(e->machine->phase!=WlUnlocking)return failed(e,WlOpState,13);
    if(!authenticated)return failed(e,WlOpUser,5);
    if(!call(e,WlOpUser,e->driver->user(e->context)))return 0;
    error=e->driver->desktop(e->context);
    if(error){
        if(!call(e,WlOpSecure,e->driver->secure(e->context)))return 0;
        if(!state(e,WlDenied,0))return 0;
        return failed(e,WlOpDesktop,error);
    }
    if(!state(e,WlUnlockCompleted,WL_UNLOCK_CHECKED|WL_USER_ACTIVE))return 0;
    return notice(e,WlNoticeUnlock);
}
int wl_engine_logoff(WL_SESSION_ENGINE *e)
{
    WL_PHASE phase;
    if(!valid(e))return 0;
    phase=e->machine->phase;
    if(phase!=WlInteractive&&phase!=WlSecurityOptions&&phase!=WlLocked&&phase!=WlUnlocking)
        return failed(e,WlOpState,13);
    if(!call(e,WlOpUser,e->driver->user(e->context))||
       !call(e,WlOpSecure,e->driver->secure(e->context))||
       !state(e,WlLogoffRequested,WL_SECURE_ACTIVE))return 0;
    if(!notice(e,WlNoticeLogoff)||!call(e,WlOpEndProcesses,e->driver->end_processes(e->context))||
       !call(e,WlOpRelease,e->driver->release(e->context)))goto fatal;
    if(!state(e,WlSessionReleased,WL_RESOURCES_GONE|WL_SECURE_ACTIVE))goto fatal;
    e->protection_attempted=e->shell_attempted=0;return 1;
fatal:
    wl_state_step(e->machine,WlFatalError,0);return 0;
}
int wl_engine_power(WL_SESSION_ENGINE *e,unsigned mode)
{
    if(!valid(e))return 0;
    if(mode>1||e->machine->phase!=WlSignedOut||e->machine->token_owned||
       e->machine->profile_owned||e->machine->shell_owned)return failed(e,WlOpState,13);
    if(!call(e,WlOpSecure,e->driver->secure(e->context))||!notice(e,WlNoticeShutdown)||
       !call(e,WlOpPower,e->driver->power(e->context,mode)))return 0;
    return state(e,WlPowerRequested,WL_SECURE_ACTIVE);
}
