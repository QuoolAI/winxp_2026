/* MerlinAI guest probe (Milestone 9 lab only; never installed).

   merlin_probe.exe cpl   enumerate the Control Panel folder through the shell
                          (the same IShellFolder Explorer uses) and report on
                          COM1 which applets it shows:
                            XP25_MERLIN_CPL_ITEM=<name>        every item
                            XP25_MERLIN_CPL_MERLIN=0|1         "MerlinAI Health and Updates"
                            XP25_MERLIN_CPL_MERLIN_CATEGORY=<n> its category as the shell
                                                               resolves it (IShellFolder2::GetDetailsEx,
                                                               what the category view uses)
                            XP25_MERLIN_CPL_SECURITY_CENTER=0|1
                            XP25_MERLIN_CPL_AUTOMATIC_UPDATES=0|1
   Exit code 0 when the enumeration itself worked. */
#define COBJMACROS
#include <windows.h>
#include <shlobj.h>

/* IShellFolder's and IShellFolder2's IIDs and the Control Panel category property
   ({305CA226-D286-468e-B848-2B2E8E697B74} 2), defined here so the probe needs no uuid library. */
static const IID shell_folder_iid = { 0x000214E6, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const IID shell_folder2_iid = { 0x93F2F68C, 0x1D1B, 0x11D3, { 0xA3, 0x0E, 0x00, 0xC0, 0x4F, 0x79, 0xAB, 0xD1 } };
static const SHCOLUMNID category_scid = { { 0x305CA226, 0xD286, 0x468E, { 0xB8, 0x48, 0x2B, 0x2E, 0x8E, 0x69, 0x7B, 0x74 } }, 2 };

/* The category the shell resolves for one Control Panel item, or -1. */
static long item_category(IShellFolder *folder, LPCITEMIDLIST child)
{
    IShellFolder2 *folder2 = NULL;
    VARIANT v;
    long category = -1;
    if (FAILED(IShellFolder_QueryInterface(folder, &shell_folder2_iid, (void **)&folder2))) return -1;
    ZeroMemory(&v, sizeof(v));                       /* VT_EMPTY, without oleaut32 */
    if (SUCCEEDED(IShellFolder2_GetDetailsEx(folder2, child, &category_scid, &v))) {
        if (v.vt == VT_I4 || v.vt == VT_INT) category = v.lVal;
        else if (v.vt == VT_UI4 || v.vt == VT_UINT) category = (long)v.ulVal;
        else category = 1000 + v.vt;                   /* another representation: reported, never matched */
    }
    IShellFolder2_Release(folder2);
    return category;
}

static void serial(const char *line)
{
    HANDLE port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD wrote;
    int tries;
    for (tries = 0; port == INVALID_HANDLE_VALUE && tries < 20; ++tries) {
        Sleep(50);                                     /* Winlogon opens COM1 exclusively per event */
        port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (port == INVALID_HANDLE_VALUE) return;
    WriteFile(port, line, (DWORD)lstrlenA(line), &wrote, NULL);
    WriteFile(port, "\r\n", 2, &wrote, NULL);
    CloseHandle(port);
}

static int cpl(void)
{
    IShellFolder *desktop = NULL, *controls = NULL;
    IEnumIDList *items = NULL;
    LPITEMIDLIST pidl = NULL, child;
    IMalloc *malloc_ = NULL;
    ULONG fetched;
    int merlin = 0, security = 0, updates = 0, count = 0;
    long merlin_category = -1;
    char line[400];
    if (FAILED(CoInitialize(NULL)) || FAILED(SHGetMalloc(&malloc_)) || FAILED(SHGetDesktopFolder(&desktop)) ||
        FAILED(SHGetSpecialFolderLocation(NULL, CSIDL_CONTROLS, &pidl)) ||
        FAILED(IShellFolder_BindToObject(desktop, pidl, NULL, &shell_folder_iid, (void **)&controls)) ||
        FAILED(IShellFolder_EnumObjects(controls, NULL, SHCONTF_NONFOLDERS | SHCONTF_FOLDERS, &items)) || !items) {
        serial("XP25_MERLIN_CPL_ENUM=failed");
        return 1;
    }
    while (IEnumIDList_Next(items, 1, &child, &fetched) == S_OK && fetched == 1) {
        STRRET name;
        WCHAR wide[260];
        wide[0] = 0;
        if (SUCCEEDED(IShellFolder_GetDisplayNameOf(controls, child, SHGDN_NORMAL, &name))) {
            if (name.uType == STRRET_WSTR) {
                lstrcpynW(wide, name.pOleStr, 260);
                IMalloc_Free(malloc_, name.pOleStr);
            } else if (name.uType == STRRET_CSTR)
                MultiByteToWideChar(CP_ACP, 0, name.cStr, -1, wide, 260);
        }
        if (wide[0] && !lstrcmpiW(wide, L"MerlinAI Health and Updates")) {
            merlin = 1;
            merlin_category = item_category(controls, child);
        }
        IMalloc_Free(malloc_, child);
        if (!wide[0]) continue;
        ++count;
        if (!lstrcmpiW(wide, L"Security Center")) security = 1;
        if (!lstrcmpiW(wide, L"Automatic Updates")) updates = 1;
        lstrcpyA(line, "XP25_MERLIN_CPL_ITEM=");
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, line + lstrlenA(line), 300, NULL, NULL);
        serial(line);
    }
    IEnumIDList_Release(items);
    IShellFolder_Release(controls);
    IShellFolder_Release(desktop);
    IMalloc_Free(malloc_, pidl);
    IMalloc_Release(malloc_);
    wsprintfA(line, "XP25_MERLIN_CPL_COUNT=%d", count);
    serial(line);
    serial(merlin ? "XP25_MERLIN_CPL_MERLIN=1" : "XP25_MERLIN_CPL_MERLIN=0");
    wsprintfA(line, "XP25_MERLIN_CPL_MERLIN_CATEGORY=%ld", merlin_category);
    serial(line);
    serial(security ? "XP25_MERLIN_CPL_SECURITY_CENTER=1" : "XP25_MERLIN_CPL_SECURITY_CENTER=0");
    serial(updates ? "XP25_MERLIN_CPL_AUTOMATIC_UPDATES=1" : "XP25_MERLIN_CPL_AUTOMATIC_UPDATES=0");
    CoUninitialize();
    return 0;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    (void)instance;
    (void)previous;
    (void)show;
    if (command_line && !lstrcmpiW(command_line, L"cpl")) return cpl();
    serial("XP25_MERLIN_PROBE_USAGE=merlin_probe.exe cpl");
    return 2;
}
