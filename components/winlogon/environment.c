#include "environment.h"
static unsigned short fold(unsigned short c)
{return c>='a'&&c<='z'?(unsigned short)(c-'a'+'A'):c;}
int wl_environment_next(const unsigned short *block,unsigned capacity,unsigned *cursor,
    const unsigned short **name,unsigned *name_length,
    const unsigned short **value,unsigned *value_length)
{
    unsigned at,end,equals;
    if(!cursor||!name||!name_length||!value||!value_length)return -1;
    *name=0;*name_length=0;*value=0;*value_length=0;at=*cursor;
    if(!block||capacity<2||at>=capacity)return -1;
    if(!block[at])return at==0&&block[1]?-1:0;
    end=at;while(end<capacity&&block[end])++end;
    if(end+1>=capacity)return -1;
    equals=at+(block[at]=='='?1:0);
    while(equals<end&&block[equals]!='=')++equals;
    if(equals==end||equals==at)return -1;
    *name=block+at;*name_length=equals-at;
    *value=block+equals+1;*value_length=end-equals-1;*cursor=end+1;return 1;
}
int wl_environment_find(const unsigned short *block,unsigned capacity,
    const unsigned short *name,const unsigned short **value,unsigned *length)
{
    unsigned at=0,i,n=0,key_length,data_length;int found=0,status;
    const unsigned short *key,*data;
    if(!value||!length)return -1;
    *value=0;*length=0;
    if(!block||capacity<2||!name||!name[0])return -1;
    while(name[n]){if(name[n]=='=')return -1;++n;}
    while((status=wl_environment_next(block,capacity,&at,&key,&key_length,&data,&data_length))==1){
        if(key_length==n){
            for(i=0;i<n&&fold(key[i])==fold(name[i]);++i){}
            if(i==n){
                if(found)return -1;
                found=1;*value=data;*length=data_length;
            }
        }
    }
    return status<0?-1:found;
}
