/* Screen-saver decisions: the documented cases, then every phase, notice, setting and GINA
   answer, checked against the rules that keep an idle session protected. */
#include <stdio.h>
#include "screensaver.h"
static unsigned failures, checks;
#define CHECK(expr) do {++checks;if (!(expr)) {++failures;printf("FAIL line %d: %s\n",__LINE__,#expr);}} while(0)

static WL_SAVER_ACTION run(WL_PHASE phase, unsigned request, unsigned active, unsigned image, unsigned secure,
                           int gina_allows, int gina_secure, unsigned *offered, unsigned *final_secure)
{
    WL_SAVER_SETTINGS s;WL_SAVER_PLACE place=wl_saver_place(phase);unsigned flag=99;
    s.active=active;s.image=image;s.secure=secure;
    if(!wl_saver_consult(place,request,&s,&flag)){*offered=flag;*final_secure=0;return WlSaverIgnore;}
    *offered=flag;
    /* MSGINA: a secure request becomes WlxIsLockOk; a GINA may also clear or set it. */
    if(gina_secure>=0)flag=(unsigned)gina_secure;
    *final_secure=flag;
    return wl_saver_decide(place,request,gina_allows,flag);
}

int main(void)
{
    unsigned p,r,a,i,s,offered,final_secure,flag;int g,gs;WL_SAVER_ACTION action;WL_SAVER_PLACE place;WL_SAVER_SETTINGS none;
    /* XP defaults: logon.scr, active, not secure. */
    CHECK(run(WlAuthenticating,0,1,1,0,1,-1,&offered,&final_secure)==WlSaverStart&&!offered);
    CHECK(run(WlAuthenticating,1,1,1,0,1,-1,&offered,&final_secure)==WlSaverStart);
    CHECK(run(WlSignedOut,0,1,1,1,1,-1,&offered,&final_secure)==WlSaverStart&&!offered);
    CHECK(run(WlInteractive,0,1,1,0,1,-1,&offered,&final_secure)==WlSaverStart&&!final_secure);
    /* A non-secure session saver waits for the application's own start notice. */
    CHECK(run(WlInteractive,1,1,1,0,1,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlInteractive,1,1,1,1,1,-1,&offered,&final_secure)==WlSaverStart&&offered&&final_secure);
    CHECK(run(WlInteractive,1,1,1,1,1,0,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlInteractive,0,1,1,1,1,0,&offered,&final_secure)==WlSaverStart&&!final_secure);
    CHECK(run(WlLocked,0,1,1,1,1,-1,&offered,&final_secure)==WlSaverStart&&!offered);
    CHECK(run(WlLocked,1,1,1,0,1,-1,&offered,&final_secure)==WlSaverStart);
    CHECK(run(WlInteractive,2,1,0,1,1,-1,&offered,&final_secure)==WlSaverLockNow);
    CHECK(run(WlInteractive,2,1,1,0,1,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlAuthenticating,2,1,1,1,1,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlInteractive,0,1,1,1,0,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlInteractive,0,0,1,1,1,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlInteractive,0,1,0,1,1,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlSecurityOptions,0,1,1,1,1,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlLoadingProfile,0,1,1,1,1,-1,&offered,&final_secure)==WlSaverIgnore);
    CHECK(run(WlUnlocking,1,1,1,1,1,-1,&offered,&final_secure)==WlSaverStart&&!offered);
    CHECK(wl_saver_return(WlSaverSession,1)==WlSaverLockSession);
    CHECK(wl_saver_return(WlSaverSession,0)==WlSaverBackToDesktop);
    CHECK(wl_saver_return(WlSaverLocked,1)==WlSaverBackToLocked);
    CHECK(wl_saver_return(WlSaverLogonDesktop,1)==WlSaverBackToLogon);
    CHECK(!wl_saver_consult(WlSaverSession,0,NULL,&flag)&&!flag);
    none.active=none.image=none.secure=1;CHECK(!wl_saver_consult(WlSaverSession,0,&none,NULL));
    CHECK(wl_saver_decide(WlSaverSession,3,1,1)==WlSaverIgnore);
    /* Every phase, notice (including an unknown one), setting and GINA answer. */
    for(p=0;p<=WlFailed;++p) for(r=0;r<=3;++r) for(a=0;a<=1;++a) for(i=0;i<=1;++i) for(s=0;s<=1;++s)
    for(g=0;g<=1;++g) for(gs=-1;gs<=1;++gs) {
        place=wl_saver_place((WL_PHASE)p);
        action=run((WL_PHASE)p,r,a,i,s,g,gs,&offered,&final_secure);
        CHECK(place==(p==WlSignedOut||p==WlAuthenticating?WlSaverLogonDesktop:p==WlInteractive?WlSaverSession:
                      p==WlLocked||p==WlUnlocking?WlSaverLocked:WlSaverNowhere));
        if(place==WlSaverNowhere||r>2||!g||!a)CHECK(action==WlSaverIgnore);
        /* Only a session offers or keeps a secure flag. */
        if(place!=WlSaverSession)CHECK(!offered&&action!=WlSaverLockNow);
        /* A saver process starts only with an existing image and never for a dark monitor. */
        if(action==WlSaverStart)CHECK(i&&r!=2);
        /* Lock at once only for a secure session saver with the monitor off. */
        if(action==WlSaverLockNow)CHECK(place==WlSaverSession&&r==2&&final_secure&&s);
        /* "Start only if secure" never starts a non-secure session saver. */
        if(place==WlSaverSession&&r==1&&action==WlSaverStart)CHECK(final_secure);
        /* After a secure session saver the session is locked, never returned. */
        if(action==WlSaverStart&&place==WlSaverSession&&final_secure)CHECK(wl_saver_return(place,final_secure)==WlSaverLockSession);
        if(action==WlSaverStart&&place==WlSaverSession&&!final_secure)CHECK(wl_saver_return(place,final_secure)==WlSaverBackToDesktop);
        if(action==WlSaverStart&&place!=WlSaverSession)CHECK(wl_saver_return(place,final_secure)!=WlSaverBackToDesktop&&
                                                              wl_saver_return(place,final_secure)!=WlSaverLockSession);
        /* Everything allowed and configured starts at the logon desktop and when locked. */
        if((place==WlSaverLogonDesktop||place==WlSaverLocked)&&r<2&&a&&i&&g)CHECK(action==WlSaverStart);
    }
    printf("WINLOGON_SCREENSAVER checks=%u failures=%u\n",checks,failures);
    return failures?1:0;
}
