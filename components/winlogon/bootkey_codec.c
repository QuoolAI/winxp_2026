#include "bootkey_codec.h"
static int hex_digit(unsigned char c)
{
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
int wl_decode_boot_classes(const char *classes[4],unsigned char key[16])
{
    /* Byte placement specified by the existing NT 5.1 Wx stored-key consumer. */
    static const unsigned char position[16]={8,10,3,7,2,1,9,15,0,5,13,4,11,6,12,14};
    unsigned group,byte,i;int high,low;
    if(!key)return 0;
    for(i=0;i<16;++i)key[i]=0;
    if(!classes)return 0;
    for(group=0;group<4;++group){
        if(!classes[group])goto invalid;
        for(i=0;i<8;++i)if(!classes[group][i])goto invalid;
        if(classes[group][8])goto invalid;
        for(byte=0;byte<4;++byte){
            high=hex_digit((unsigned char)classes[group][2*byte]);low=hex_digit((unsigned char)classes[group][2*byte+1]);
            if(high<0||low<0)goto invalid;
            key[position[4*group+byte]]=(unsigned char)((high<<4)|low);
        }
    }
    return 1;
invalid:
    for(i=0;i<16;++i)key[i]=0;
    return 0;
}
