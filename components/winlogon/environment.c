#include "environment.h"
static unsigned short fold(unsigned short c)
{return c>='a'&&c<='z'?(unsigned short)(c-'a'+'A'):c;}
int wl_environment_find(const unsigned short *block,unsigned capacity,
    const unsigned short *name,const unsigned short **value,unsigned *length)
{
    unsigned at=0,end,equals,i,n=0;int found=0;
    if(!value||!length)return -1;
    *value=0;*length=0;
    if(!block||capacity<2||!name||!name[0])return -1;
    while(name[n]){if(name[n]=='=')return -1;++n;}
    if(!block[0])return block[1]?-1:0;
    while(at<capacity){
        end=at;while(end<capacity&&block[end])++end;
        if(end==capacity)return -1;
        equals=at+(block[at]=='='?1:0);
        while(equals<end&&block[equals]!='=')++equals;
        if(equals==end||equals==at)return -1;
        if(equals-at==n){
            for(i=0;i<n&&fold(block[at+i])==fold(name[i]);++i){}
            if(i==n){
                if(found)return -1;
                found=1;*value=block+equals+1;*length=end-equals-1;
            }
        }
        if(end+1>=capacity)return -1;
        if(!block[end+1])return found;
        at=end+1;
    }
    return -1;
}
