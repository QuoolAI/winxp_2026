/* Bounded UTF-16 environment inspection; independent of host wchar_t size. */
#ifndef XP25_WINLOGON_ENVIRONMENT_H
#define XP25_WINLOGON_ENVIRONMENT_H
/* 1 = found, 0 = absent, -1 = malformed. Capacity is in UTF-16 code units.
   Validate the entire block, including duplicate matches and double NUL. */
int wl_environment_find(const unsigned short *block,unsigned capacity,
    const unsigned short *name,const unsigned short **value,unsigned *length);
#endif
