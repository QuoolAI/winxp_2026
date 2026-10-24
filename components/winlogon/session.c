/* XP25 stage boundary. The original binary embeds activation policy routines.
   No independently verified replacement contract exists yet. A successful GINA
   result must not turn omission of that policy into permission to run a shell. */
#include "platform.h"
BOOL wl_session_start(void)
{
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    wl_log("activation_and_session_contract_unimplemented",ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
BOOL wl_session_end(void)
{
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return FALSE;
}
