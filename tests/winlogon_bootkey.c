/* Synthetic vectors only. No real registry values or startup secrets. */
#include <stdio.h>
#include <string.h>
#include "bootkey_codec.h"
int main(void)
{
    const char *classes[4]={"00010203","04050607","08090a0b","0c0d0e0f"};
    const unsigned char expected[16]={8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7};
    unsigned char key[16],zero[16]={0};unsigned failures=0;
    if(!wl_decode_boot_classes(classes,key)||memcmp(key,expected,16))++failures;
    classes[0]="0001020Z";if(wl_decode_boot_classes(classes,key)||memcmp(key,zero,16))++failures;
    classes[0]="000102";if(wl_decode_boot_classes(classes,key)||memcmp(key,zero,16))++failures;
    classes[0]="000102030";if(wl_decode_boot_classes(classes,key)||memcmp(key,zero,16))++failures;
    classes[0]=NULL;if(wl_decode_boot_classes(classes,key)||memcmp(key,zero,16))++failures;
    if(wl_decode_boot_classes(NULL,key)||memcmp(key,zero,16))++failures;
    if(wl_decode_boot_classes(classes,NULL))++failures;
    printf("WINLOGON_BOOTKEY cases=7 failures=%u\n",failures);return failures?1:0;
}
