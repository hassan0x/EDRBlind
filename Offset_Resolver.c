/*
 * Offset_Resolver.c -- kernel symbol resolver
 *
 * Downloads ntoskrnl.pdb from msdl.microsoft.com via dbghelp.dll and
 * resolves the RVAs of all kernel globals and _EPROCESS field offsets
 * needed by EDRBlind. Outputs config.txt in the current directory.
 */

#include <Windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#define LOG_INFO(...) (printf("[*] "), printf(__VA_ARGS__), putchar('\n'))
#define LOG_OK(...)   (printf("[+] "), printf(__VA_ARGS__), putchar('\n'))
#define LOG_ERR(...)  (printf("[-] "), printf(__VA_ARGS__), putchar('\n'))
#define LOG_WARN(...) (printf("[!] "), printf(__VA_ARGS__), putchar('\n'))

#define SYMBOL_SERVER  "https://msdl.microsoft.com/download/symbols"
#define SYMBOL_CACHE   "C:\\Symbols"
#define SYMBOL_PATH    "srv*" SYMBOL_CACHE "*" SYMBOL_SERVER
#define SYM_FAKE_BASE  0x10000000ULL
#define CFG_FILE       "config.txt"

typedef struct {
    DWORD64 PspCreateProcessNotifyRoutine;
    DWORD64 PspCreateThreadNotifyRoutine;
    DWORD64 PspLoadImageNotifyRoutine;
    DWORD64 ObTypeIndexTable;
    DWORD64 CallbackListHead;
    DWORD64 EtwpDebuggerData;
    DWORD64 PsInitialSystemProcess;
    DWORD   EtwpGuidHashTableOff;
    DWORD   EprocLinksOff;
    DWORD   EprocNameOff;
    DWORD   EprocProtOff;
} KERN_OFFSETS;

static KERN_OFFSETS g_offsets;


static DWORD udt_field_off(HANDLE hproc, DWORD64 pdb_base,
                           const char *type_name, const WCHAR *field_name)
{
    char                    sbuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    SYMBOL_INFO            *sym = (SYMBOL_INFO *)sbuf;
    DWORD                   child_count = 0, i, offset = 0;
    TI_FINDCHILDREN_PARAMS *children;

    memset(sbuf, 0, sizeof sbuf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = MAX_SYM_NAME;
    if (!SymGetTypeFromName(hproc, pdb_base, type_name, sym)) return 0;

    if (!SymGetTypeInfo(hproc, pdb_base, sym->TypeIndex,
                        TI_GET_CHILDRENCOUNT, &child_count) || !child_count) return 0;

    children = (TI_FINDCHILDREN_PARAMS *)
               calloc(1, sizeof(*children) + child_count * sizeof(ULONG));
    if (!children) return 0;

    children->Count = child_count;
    if (SymGetTypeInfo(hproc, pdb_base, sym->TypeIndex, TI_FINDCHILDREN, children)) {
        for (i = 0; i < child_count && !offset; i++) {
            WCHAR *sname = NULL;
            if (SymGetTypeInfo(hproc, pdb_base, children->ChildId[i],
                               TI_GET_SYMNAME, &sname) && sname) {
                if (wcscmp(sname, field_name) == 0)
                    SymGetTypeInfo(hproc, pdb_base, children->ChildId[i],
                                   TI_GET_OFFSET, &offset);
                LocalFree(sname);
            }
        }
    }
    free(children);
    return offset;
}

static BOOL resolve_offsets(void)
{
    typedef struct { const char *name; DWORD64 *dest; } SYM_MAP;

    SYM_MAP map[] = {
        { "PspCreateProcessNotifyRoutine", &g_offsets.PspCreateProcessNotifyRoutine },
        { "PspCreateThreadNotifyRoutine",  &g_offsets.PspCreateThreadNotifyRoutine  },
        { "PspLoadImageNotifyRoutine",     &g_offsets.PspLoadImageNotifyRoutine     },
        { "ObTypeIndexTable",              &g_offsets.ObTypeIndexTable              },
        { "CallbackListHead",              &g_offsets.CallbackListHead              },
        { "EtwpDebuggerData",              &g_offsets.EtwpDebuggerData              },
        { "PsInitialSystemProcess",        &g_offsets.PsInitialSystemProcess        },
    };
    const int N = sizeof map / sizeof map[0];

    char        sbuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    SYMBOL_INFO *sym   = (SYMBOL_INFO *)sbuf;
    HANDLE       hproc = GetCurrentProcess();
    char         sysdir[MAX_PATH], ntoskrnl[MAX_PATH];
    DWORD64      pdb_base;
    int          i;

    GetSystemDirectoryA(sysdir, sizeof sysdir);
    _snprintf_s(ntoskrnl, sizeof ntoskrnl, _TRUNCATE, "%s\\ntoskrnl.exe", sysdir);
    LOG_INFO("Resolving symbols from %s", ntoskrnl);

    LoadLibraryA("dbghelp.dll");
    SymSetOptions(SYMOPT_UNDNAME);

    if (!SymInitialize(hproc, SYMBOL_PATH, FALSE)) {
        LOG_ERR("SymInitialize failed (%lu)", GetLastError());
        return FALSE;
    }

    pdb_base = SymLoadModuleEx(hproc, NULL, ntoskrnl, NULL, SYM_FAKE_BASE, 0, NULL, 0);
    if (!pdb_base) {
        LOG_ERR("SymLoadModuleEx failed (%lu) -- is msdl.microsoft.com reachable?",
                GetLastError());
        SymCleanup(hproc);
        return FALSE;
    }

    LOG_OK("PDB loaded for %s", ntoskrnl);

    for (i = 0; i < N; i++) {
        memset(sbuf, 0, sizeof sbuf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen   = MAX_SYM_NAME;
        if (!SymFromName(hproc, map[i].name, sym)) {
            LOG_ERR("SymFromName(%s) failed (%lu)", map[i].name, GetLastError());
            SymCleanup(hproc);
            return FALSE;
        }
        *map[i].dest = sym->Address - pdb_base;
        LOG_OK("%-42s  RVA 0x%llX", map[i].name, (unsigned long long)*map[i].dest);
    }

    g_offsets.EprocLinksOff = udt_field_off(hproc, pdb_base, "_EPROCESS",
                                             L"ActiveProcessLinks");
    g_offsets.EprocNameOff  = udt_field_off(hproc, pdb_base, "_EPROCESS",
                                             L"ImageFileName");
    g_offsets.EprocProtOff  = udt_field_off(hproc, pdb_base, "_EPROCESS",
                                             L"Protection");

    if (!g_offsets.EprocLinksOff || !g_offsets.EprocNameOff || !g_offsets.EprocProtOff) {
        LOG_ERR("_EPROCESS offsets unresolved");
        SymCleanup(hproc);
        return FALSE;
    }

    LOG_OK("_EPROCESS.ActiveProcessLinks  +0x%X", g_offsets.EprocLinksOff);
    LOG_OK("_EPROCESS.ImageFileName        +0x%X", g_offsets.EprocNameOff);
    LOG_OK("_EPROCESS.Protection           +0x%X", g_offsets.EprocProtOff);

    g_offsets.EtwpGuidHashTableOff = udt_field_off(hproc, pdb_base,
                                         "_ETW_SILODRIVERSTATE", L"EtwpGuidHashTable");
    if (!g_offsets.EtwpGuidHashTableOff) {
        LOG_ERR("_ETW_SILODRIVERSTATE.EtwpGuidHashTable not found in PDB");
        SymCleanup(hproc);
        return FALSE;
    }
    LOG_OK("EtwpGuidHashTableOff  +0x%X", g_offsets.EtwpGuidHashTableOff);

    SymCleanup(hproc);
    return TRUE;
}

static BOOL write_config(const char *path)
{
    FILE *fp;
    if (fopen_s(&fp, path, "w") != 0 || !fp) {
        LOG_ERR("Cannot write %s", path);
        return FALSE;
    }
    fprintf(fp, "PspCreateProcessNotifyRoutine=0x%016llX\n",
            (unsigned long long)g_offsets.PspCreateProcessNotifyRoutine);
    fprintf(fp, "PspCreateThreadNotifyRoutine=0x%016llX\n",
            (unsigned long long)g_offsets.PspCreateThreadNotifyRoutine);
    fprintf(fp, "PspLoadImageNotifyRoutine=0x%016llX\n",
            (unsigned long long)g_offsets.PspLoadImageNotifyRoutine);
    fprintf(fp, "ObTypeIndexTable=0x%016llX\n",
            (unsigned long long)g_offsets.ObTypeIndexTable);
    fprintf(fp, "CallbackListHead=0x%016llX\n",
            (unsigned long long)g_offsets.CallbackListHead);
    fprintf(fp, "EtwpDebuggerData=0x%016llX\n",
            (unsigned long long)g_offsets.EtwpDebuggerData);
    fprintf(fp, "PsInitialSystemProcess=0x%016llX\n",
            (unsigned long long)g_offsets.PsInitialSystemProcess);
    fprintf(fp, "EtwpGuidHashTableOff=0x%X\n", g_offsets.EtwpGuidHashTableOff);
    fprintf(fp, "EprocLinksOff=0x%X\n",        g_offsets.EprocLinksOff);
    fprintf(fp, "EprocNameOff=0x%X\n",          g_offsets.EprocNameOff);
    fprintf(fp, "EprocProtOff=0x%X\n",          g_offsets.EprocProtOff);
    fclose(fp);
    LOG_OK("Config written to %s", path);
    return TRUE;
}

int main(void)
{
    printf("Offset_Resolver.exe -- kernel symbol resolver\n\n");
    if (!resolve_offsets()) return 1;
    printf("\n");
    if (!write_config(CFG_FILE)) return 1;
    LOG_INFO("Run EDRBlind.exe after RTCore64.sys is loaded.");
    return 0;
}
