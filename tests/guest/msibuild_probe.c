/* Builds the compatibility suite's fixture MSI (C:\xp25\branding-fixture.msi) from
   the .idt tables in D:\msi with msi.dll's database API: the native form of
   msi-build.vbs, for images without the VBScript engine (build/ie_removal.py).
   Exit 0 when the database is created and committed, otherwise the MSI error. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <msiquery.h>

void WINAPI ProbeMain(void)
{
    static const WCHAR *const tables[] = {L"_SummaryInformation", L"Property", L"Directory", L"Media", L"Component",
                                           L"Feature", L"FeatureComponents", L"Registry", L"LaunchCondition", L"InstallExecuteSequence"};
    static const WCHAR path[] = L"C:\\xp25\\branding-fixture.msi";
    WCHAR file[64];
    char row[160];
    MSIHANDLE db = 0;
    UINT error, i;
    DWORD n;
    DeleteFileW(path);
    error = MsiOpenDatabaseW(path, (LPCWSTR)MSIDBOPEN_CREATE, &db);
    for (i = 0; !error && i < sizeof(tables) / sizeof(tables[0]); ++i) {
        wsprintfW(file, L"%s.idt", tables[i]);
        error = MsiDatabaseImportW(db, L"D:\\msi", file);
    }
    if (!error) error = MsiDatabaseCommit(db);
    if (db) MsiCloseHandle(db);
    wsprintfA(row, error ? "XP25 fixture MSI database failed: table %u, error %u\r\n" : "XP25 fixture MSI database created\r\n", i, error);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), row, lstrlenA(row), &n, NULL);
    ExitProcess(error);
}
