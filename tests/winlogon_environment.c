/* Bounded parsing behavior, including malformed blocks after a matching key. */
#include <stdio.h>
#include <string.h>
#include "environment.h"
static unsigned failures,checks;
static unsigned short wide[256],key[32];
static void check(const char *block,unsigned count,const char *name,int expected,const char *result)
{
    unsigned i,length=0;const unsigned short *value=0;int status;
    for(i=0;i<count;++i)wide[i]=(unsigned char)block[i];
    for(i=0;name[i];++i)key[i]=(unsigned char)name[i];
    key[i]=0;
    status=wl_environment_find(wide,count,key,&value,&length);++checks;
    if(status!=expected){++failures;return;}
    if(status==1){
        if(length!=strlen(result)){++failures;return;}
        for(i=0;i<length;++i)if(value[i]!=(unsigned char)result[i]){++failures;break;}
    }
}
static void walk(const char *block,unsigned count,int expected_entries,int expected_status)
{
    unsigned i,at=0,names,values;int entries=0,status;
    const unsigned short *name,*value;
    for(i=0;i<count;++i)wide[i]=(unsigned char)block[i];
    while((status=wl_environment_next(wide,count,&at,&name,&names,&value,&values))==1){
        if(!names||name<wide||value<name||value+values>=wide+count||at>=count){++failures;break;}
        ++entries;
        if(entries>128){++failures;break;}
    }
    ++checks;if(entries!=expected_entries||status!=expected_status){
        printf("walk case %u: entries=%d status=%d\n",checks,entries,status);++failures;
    }
}
int main(void)
{
    static const char normal[]="USERNAME=XP25\0USERPROFILE=C:\\Users\\XP25\0";
    static const char duplicate[]="USERNAME=A\0UserName=B\0";
    static const char malformed[]="USERNAME=A\0BROKEN\0";
    static const char drive[]="=C:=C:\\WINDOWS\0USERNAME=XP25\0";
    static const char prefix[]="USERNAMEX=A\0";
    static const unsigned short unicode[]={85,83,69,82,78,65,77,69,61,0xe9,0x6f22,0,0};
    static const unsigned short name[]={85,83,69,82,78,65,77,69,0};
    const unsigned short *value=0;unsigned length=0;
    check(normal,sizeof(normal),"USERNAME",1,"XP25");
    check(normal,sizeof(normal),"username",1,"XP25");
    check(normal,sizeof(normal),"MISSING",0,"");
    check(normal,sizeof(normal)-1,"USERNAME",-1,"");
    check("\0",1,"USERNAME",-1,"");
    check("\0",2,"USERNAME",0,"");
    check(duplicate,sizeof(duplicate),"USERNAME",-1,"");
    check(malformed,sizeof(malformed),"USERNAME",-1,"");
    check(drive,sizeof(drive),"USERNAME",1,"XP25");
    check(prefix,sizeof(prefix),"USERNAME",0,"");
    check(normal,sizeof(normal),"USER=NAME",-1,"");
    ++checks;if(wl_environment_find(unicode,sizeof(unicode)/sizeof(unicode[0]),name,&value,&length)!=1||
       length!=2||value[0]!=0xe9||value[1]!=0x6f22)++failures;
    ++checks;if(wl_environment_find(0,2,name,&value,&length)!=-1)++failures;
    walk(normal,sizeof(normal),2,0);
    walk(normal,sizeof(normal)-1,1,-1);
    walk(normal,sizeof(normal)-2,1,-1);
    walk("\0",2,0,0);
    walk("\0",1,0,-1);
    walk("\0X",3,0,-1);
    walk(malformed,sizeof(malformed),1,-1);
    walk(drive,sizeof(drive),2,0);
    walk("EMPTY=\0",8,1,0);
    walk("=value\0",8,0,-1);
    walk("X=%USERPROFILE%\\path\0",22,1,0);
    printf("WINLOGON_ENVIRONMENT cases=%u failures=%u\n",checks,failures);return failures?1:0;
}
