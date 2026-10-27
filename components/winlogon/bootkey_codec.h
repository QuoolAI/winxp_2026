/* XP25 parser for the NT 5.1 stored startup-key registry-class wire format. */
#ifndef XP25_BOOTKEY_CODEC_H
#define XP25_BOOTKEY_CODEC_H
int wl_decode_boot_classes(const char *classes[4],unsigned char key[16]);
#endif
