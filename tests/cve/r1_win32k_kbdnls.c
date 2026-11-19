/* R-1 regression: win32k.sys FarEast keyboard-layout NLS dispatch in
   windows/core/ntuser/kernel/fekbd.c (MS10-073 class). The function index and function type
   come from the NLS table of a keyboard layout, which any user can load, and select an
   entry of win32k's function tables.

   extracted.c (written by tests/test_cve.py) holds GenerateNlsVkKey, GenerateNlsVkAltKey and
   xxxKENLSProcs verbatim, original or patched. The two tables are modelled with the entry
   counts of the real ones (NLSKE_COUNT, NLSVKF_COUNT, read from fekbd.c by the test); each
   entry only records that it was called. The tables are globals of this instrumented
   program, so AddressSanitizer sees an index past their end.

   usage: r1_win32k_kbdnls valid|index|alt-index|type   exit 0 = the expectation holds */
#include "nt_shim.h"

typedef struct { BYTE NLSFEProcIndex; ULONG NLSFEProcParam; } VK_FPARAM;
typedef struct {
    BYTE Vk, NLSFEProcType, NLSFEProcCurrent, NLSFEProcSwitch;
    VK_FPARAM NLSFEProc[8];
    VK_FPARAM NLSFEProcAlt[8];
} VK_F, *PVK_F;
typedef struct { USHORT OEMIdentifier, LayoutInformation; UINT NumOfVkToF; PVK_F pVkToF; } KBDNLSTABLES, *PKBDNLSTABLES;
typedef struct { USHORT usFlaggedVk; } KE, *PKE;
typedef BOOL (*NLSKEPROC)(PKE, ULONG_PTR, ULONG);
typedef BOOL (*NLSVKFPROC)(PVK_F, PKE, ULONG_PTR);

#define LOBYTE(w) ((BYTE)((w) & 0xff))
#define RIP_WARNING 0
#define RIPMSG1(f, s, a) ((void)0)
#define CheckCritIn() ((void)0)

static int called = -1;
static PKBDNLSTABLES gpKbdNlsTbl;

#define KE_ENTRY(n) static BOOL ke##n(PKE k, ULONG_PTR x, ULONG p) { (void)k; (void)x; (void)p; called = n; return TRUE; }
KE_ENTRY(0) KE_ENTRY(1) KE_ENTRY(2) KE_ENTRY(3) KE_ENTRY(4) KE_ENTRY(5) KE_ENTRY(6) KE_ENTRY(7) KE_ENTRY(8) KE_ENTRY(9)
KE_ENTRY(10) KE_ENTRY(11) KE_ENTRY(12) KE_ENTRY(13) KE_ENTRY(14) KE_ENTRY(15) KE_ENTRY(16) KE_ENTRY(17) KE_ENTRY(18) KE_ENTRY(19)
static NLSKEPROC all_ke[] = {ke0, ke1, ke2, ke3, ke4, ke5, ke6, ke7, ke8, ke9, ke10, ke11, ke12, ke13, ke14, ke15, ke16, ke17, ke18, ke19};
NLSKEPROC aNLSKEProc[NLSKE_COUNT];

BOOL GenerateNlsVkKey(PVK_F pVkToF, WORD nMod, PKE pKe, ULONG_PTR dwExtraInfo);
BOOL GenerateNlsVkAltKey(PVK_F pVkToF, WORD nMod, PKE pKe, ULONG_PTR dwExtraInfo);
static BOOL type_dummy(PVK_F f, PKE k, ULONG_PTR x) { (void)f; (void)k; (void)x; called = 100; return TRUE; }
static BOOL type_normal(PVK_F f, PKE k, ULONG_PTR x) { return GenerateNlsVkKey(f, 0, k, x); }
static BOOL type_alt(PVK_F f, PKE k, ULONG_PTR x) { return GenerateNlsVkAltKey(f, 0, k, x); }
static NLSVKFPROC all_vkf[] = {type_dummy, type_normal, type_alt};
NLSVKFPROC aNLSVKFProc[NLSVKF_COUNT];

#include "extracted.c"

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";
    static VK_F entry;
    static KBDNLSTABLES table;
    KE ke;
    BOOL result;
    int i;
    for (i = 0; i < NLSKE_COUNT && i < 20; i++) aNLSKEProc[i] = all_ke[i];
    for (i = 0; i < NLSVKF_COUNT && i < 3; i++) aNLSVKFProc[i] = all_vkf[i];
    entry.Vk = 0x15;                                  /* VK_KANA */
    entry.NLSFEProcType = 1;                          /* KBDNLS_TYPE_NORMAL */
    entry.NLSFEProc[0].NLSFEProcIndex = 1;
    entry.NLSFEProcAlt[0].NLSFEProcIndex = 2;
    table.NumOfVkToF = 1; table.pVkToF = &entry;
    gpKbdNlsTbl = &table;
    ke.usFlaggedVk = 0x15;
    if (!strcmp(mode, "valid")) {
        result = xxxKENLSProcs(&ke, 0);
        printf("called=%d result=%d\n", called, result);
        if (called != 1 || !result) return 1;
        entry.NLSFEProcType = 2; called = -1;
        result = xxxKENLSProcs(&ke, 0);
        printf("called=%d result=%d\n", called, result);
        return called != 2 || !result;
    }
    if (!strcmp(mode, "index")) {
        /* A function index one past the table. */
        entry.NLSFEProc[0].NLSFEProcIndex = NLSKE_COUNT;
        result = xxxKENLSProcs(&ke, 0);
        return called != -1 || !result;               /* passed on unchanged, nothing called */
    }
    if (!strcmp(mode, "alt-index")) {
        entry.NLSFEProcType = 2;
        entry.NLSFEProcAlt[0].NLSFEProcIndex = 255;
        result = xxxKENLSProcs(&ke, 0);
        return called != -1 || !result;
    }
    if (!strcmp(mode, "type")) {
        /* A function type one past the type table. */
        entry.NLSFEProcType = NLSVKF_COUNT;
        result = xxxKENLSProcs(&ke, 0);
        return called != -1 || !result;
    }
    return 2;
}
