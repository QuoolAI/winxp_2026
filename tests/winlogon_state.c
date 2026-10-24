/* Behavioral sequences and exhaustive checks against unsafe transitions. */
#include <stdio.h>
#include <string.h>
#include "state.h"
static unsigned failures, checks;
#define CHECK(expr) do {++checks;if (!(expr)) {++failures;printf("FAIL line %d: %s\n",__LINE__,#expr);}} while(0)
static void signed_out(WL_MACHINE *m) {wl_state_init(m);CHECK(wl_state_step(m,WlBootReady,WL_BOOT_FACTS));}
static void signed_in(WL_MACHINE *m) {
    signed_out(m);CHECK(wl_state_step(m,WlAttention,WL_SECURE_ACTIVE));
    CHECK(wl_state_step(m,WlAuthenticated,WL_TOKEN_CHECKED));
    CHECK(wl_state_step(m,WlProfileReady,WL_PROFILE_LOADED));
    CHECK(wl_state_step(m,WlShellReady,WL_SHELL_USER|WL_USER_ACTIVE));
}
int main(void) {
    WL_MACHINE m,copy;unsigned p,e,f;
    signed_out(&m);CHECK(wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE));
    copy=m;CHECK(!wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE));CHECK(memcmp(&m,&copy,sizeof(m))==0);
    CHECK(!wl_state_step(&m,WlAuthenticated,0));CHECK(wl_state_step(&m,WlDenied,0));CHECK(m.phase==WlSignedOut&&!m.token_owned);
    CHECK(wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE));CHECK(wl_state_step(&m,WlCancelled,0));
    signed_in(&m);CHECK(wl_state_step(&m,WlLockCompleted,WL_SECURE_ACTIVE));
    CHECK(wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE));CHECK(!wl_state_step(&m,WlUnlockCompleted,WL_USER_ACTIVE));
    CHECK(wl_state_step(&m,WlDenied,0));CHECK(m.phase==WlLocked&&m.token_owned);
    CHECK(wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE));CHECK(wl_state_step(&m,WlUnlockCompleted,WL_UNLOCK_CHECKED|WL_USER_ACTIVE));
    CHECK(wl_state_step(&m,WlLogoffRequested,WL_SECURE_ACTIVE));CHECK(!wl_state_step(&m,WlSessionReleased,WL_SECURE_ACTIVE));
    CHECK(wl_state_step(&m,WlSessionReleased,WL_RESOURCES_GONE|WL_SECURE_ACTIVE));CHECK(m.generation==1&&!m.token_owned&&!m.profile_owned&&!m.shell_owned);
    CHECK(wl_state_step(&m,WlPowerRequested,WL_SECURE_ACTIVE));
    signed_out(&m);CHECK(wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE));CHECK(wl_state_step(&m,WlAuthenticated,WL_TOKEN_CHECKED));
    CHECK(!wl_state_step(&m,WlRollbackCompleted,WL_SECURE_ACTIVE));CHECK(wl_state_step(&m,WlRollbackCompleted,WL_SECURE_ACTIVE|WL_RESOURCES_GONE));
    /* All missing-fact combinations: no unauthenticated path may reach desktop. */
    for(p=0;p<=WlFailed;++p) for(e=0;e<=WlFatalError;++e) for(f=0;f<=0x7ff;++f) {
        wl_state_init(&m);m.phase=(WL_PHASE)p;
        m.token_owned=p>=WlLoadingProfile&&p<=WlLoggingOff;
        m.profile_owned=p>=WlStartingShell&&p<=WlLoggingOff;
        m.shell_owned=p>=WlInteractive&&p<=WlLoggingOff;
        copy=m;
        if(!wl_state_step(&m,(WL_EVENT)e,f)) CHECK(memcmp(&m,&copy,sizeof(m))==0);
        if(m.phase==WlInteractive) CHECK(m.token_owned&&m.profile_owned&&m.shell_owned);
    }
    printf("WINLOGON_STATE checks=%u failures=%u\n",checks,failures);
    return failures?1:0;
}
