/* xp25agent.dll: the shared XP25 agent runtime used by ClippyAI, RoverAI,
   the RoverAI Explorer bar and the privileged broker. */
#include <windows.h>

HINSTANCE xp25w_module;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        xp25w_module = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
