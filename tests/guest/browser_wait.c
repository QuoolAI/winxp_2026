/* Test-only delay: no ICMP/network dependency in timing or shutdown fixtures. */
#define _WIN32_WINNT 0x0501
#include <windows.h>
void WINAPI WaitMain(void) { Sleep(5000); ExitProcess(0); }
