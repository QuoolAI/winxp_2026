/* C89 session orchestration shared by the native adapter and separate tests.
   Production binds one static native driver; there is no runtime driver setter. */
#ifndef XP25_SESSION_ENGINE_H
#define XP25_SESSION_ENGINE_H
#include "state.h"
#include "policy.h"
typedef enum {
    WlOpNone, WlOpUser, WlOpProfile, WlOpPolicy, WlOpCopyEnvironment,
    WlOpSecure, WlOpProtection, WlOpActivate, WlOpShellIdentity,
    WlOpDesktop, WlOpNotification, WlOpEndProcesses, WlOpRelease, WlOpState, WlOpPower
} WL_SESSION_OPERATION;
typedef enum { WlNoticeLogon, WlNoticeStartShell, WlNoticePostShell,
    WlNoticeLock, WlNoticeUnlock, WlNoticeLogoff, WlNoticeShutdown } WL_SESSION_NOTICE;
typedef struct {
    unsigned long (*user)(void*);
    unsigned long (*profile)(void*);
    void (*policy)(void*,WL_POLICY_RESULT*);
    unsigned long (*copy_environment)(void*,void**);
    unsigned long (*discard_environment)(void*,void*);
    unsigned long (*secure)(void*);
    unsigned long (*protect)(void*);
    /* Entry transfers the copy even on failure. The driver must account for
       GINA/child ownership during release; the engine never frees it twice. */
    unsigned long (*activate)(void*,void*);
    unsigned long (*shell_identity)(void*);
    unsigned long (*desktop)(void*);
    unsigned long (*notify)(void*,WL_SESSION_NOTICE);
    /* Success must mean user processes are gone, not merely a logoff request. */
    unsigned long (*end_processes)(void*);
    unsigned long (*release)(void*);
    unsigned long (*power)(void*,unsigned);
} WL_SESSION_DRIVER;
typedef struct {
    WL_MACHINE *machine;
    const WL_SESSION_DRIVER *driver;
    void *context,*environment_copy;
    unsigned protection_attempted,shell_attempted;
    unsigned long error;
    WL_SESSION_OPERATION operation;
    WL_POLICY_RESULT policy_result;
} WL_SESSION_ENGINE;
void wl_engine_bind(WL_SESSION_ENGINE*,WL_MACHINE*,const WL_SESSION_DRIVER*,void*);
int wl_engine_start(WL_SESSION_ENGINE*);
int wl_engine_abort(WL_SESSION_ENGINE*);
int wl_engine_lock(WL_SESSION_ENGINE*);
int wl_engine_unlock(WL_SESSION_ENGINE*,int authenticated_by_gina);
int wl_engine_logoff(WL_SESSION_ENGINE*);
int wl_engine_power(WL_SESSION_ENGINE*,unsigned mode);
#endif
