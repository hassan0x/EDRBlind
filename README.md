# EDRBlind

A BYOVD (Bring Your Own Vulnerable Driver) post-exploitation tool that blinds EDR/AV products by directly tampering with Windows kernel structures. Uses the **RTCore64** vulnerable driver for arbitrary kernel read/write, then targets five defensive mechanisms across three modules:

| Mechanism | What it blocks |
|-----------|----------------|
| Process/Thread/ImageLoad notify callbacks | EDR visibility into process creation, thread creation, image loads |
| Object callbacks (ObCallbacks) | EDR handle interception on process/thread objects |
| Registry callbacks | EDR registry monitoring |
| ETW Threat Intelligence (ETW-TI) | Kernel telemetry for memory operations (alloc, map, inject) |
| PPL (Protected Process Light) | Protection preventing termination of security processes |

---

## Files

| File | Description |
|------|-------------|
| `Offset_Resolver.c` / `.exe` | Resolves kernel symbol RVAs from ntoskrnl PDB → writes `config.txt` |
| `EDRBlind.c` / `.exe` | Main tool: callbacks, ETW-TI, PPL via RTCore64 |
| `RTCore64.sys` | Vulnerable MSI driver — BYOVD kernel R/W primitive |
| `dbghelp.dll` | PDB parsing (required by Offset_Resolver) |
| `symsrv.dll` | PDB download from Microsoft symbol server |
| `config.txt` | Kernel offsets output — read by EDRBlind at runtime |
| `build.bat` | Compiles both tools and loads RTCore64.sys |

---

## How It Works

### Step 1 — Resolve offsets (`Offset_Resolver.exe`)

Reads `ntoskrnl.exe` from disk, downloads its PDB from `msdl.microsoft.com` via `dbghelp.dll`, and resolves the RVAs of all required kernel globals and `_EPROCESS` field offsets. Writes them to `config.txt`.

Symbols resolved:

| Symbol | Use |
|--------|-----|
| `PspCreateProcessNotifyRoutine` | 64-slot array, process notify callbacks |
| `PspCreateThreadNotifyRoutine` | 64-slot array, thread notify callbacks |
| `PspLoadImageNotifyRoutine` | 64-slot array, image load callbacks |
| `ObTypeIndexTable` | Pointer array to `_OBJECT_TYPE` structs (index 7=Process, 8=Thread) |
| `CallbackListHead` | Head of registry callback linked list |
| `EtwpDebuggerData` | ETW silo pointer source (`+0x18`) |
| `PsInitialSystemProcess` | System EPROCESS — head of process list |
| `_EPROCESS.ActiveProcessLinks` | Field offset for list walk |
| `_EPROCESS.ImageFileName` | Field offset for process name |
| `_EPROCESS.Protection` | Field offset for `_PS_PROTECTION` byte |
| `EtwpGuidHashTableOff` | Offset of `EtwpGuidHashTable` in `_ETW_SILODRIVERSTATE` — resolved from PDB |

### Step 2 — Load RTCore64.sys

The driver must be loaded before running `EDRBlind.exe`. `build.bat` handles this automatically. Manual load:

```bat
copy RTCore64.sys C:\Windows\Temp\RTCore64.sys
sc create RTCore64 type= kernel binpath= C:\Windows\Temp\RTCore64.sys
sc start RTCore64
```

RTCore64 exposes two IOCTLs:
- `0x80002048` — read 4 bytes from any kernel address
- `0x8000204C` — write 4 bytes to any kernel address

These are composed into `kread32/64` and `kwrite8/32/64` helpers used by all three modules.

### Step 3 — Run EDRBlind.exe

```
EDRBlind.exe <module> <subcommand> [targets...]
```

Requires Administrator — run from an elevated prompt.

---

## Commands

### `callbacks list`

Lists all registered kernel callbacks across all five types.

```
EDRBlind.exe callbacks list
```

- **`PspCreateProcessNotifyRoutine`** — 64-slot array (`EX_FAST_REF` tagged pointers, low 4 bits stripped). Reads `_EX_CALLBACK_ROUTINE_BLOCK.Function` at `+0x08` of each block.
- **`PspCreateThreadNotifyRoutine`** — same layout
- **`PspLoadImageNotifyRoutine`** — same layout
- **ObCallbacks** — linked list at `_OBJECT_TYPE.CallbackList (+0x0C8)`. Each `CALLBACK_ENTRY_ITEM` has `Active (+0x014)`, `PreOperation (+0x028)`, `PostOperation (+0x030)`.
- **Registry callbacks** — linked list at `CallbackListHead`. Each `_CMREG_CALLBACK` has `Function (+0x028)`.

Each entry prints the function pointer address and the owning driver name.

---

### `callbacks delete <driver.sys> [...]`

Removes all callbacks registered by the named driver(s).

```
EDRBlind.exe callbacks delete WdFilter.sys
```

- **Notify arrays**: zeroes the slot → kernel skips NULL entries
- **ObCallbacks**: writes `0` to `CALLBACK_ENTRY_ITEM.Active (+0x014)` → kernel skips inactive entries; list stays intact (do not unlink — the kernel frees these itself)
- **Registry**: unlinks the node by fixing `FLINK`/`BLINK` of the surrounding nodes

---

### `etwti list`

Shows the state of the `Microsoft-Windows-Threat-Intelligence` ETW provider.

```
EDRBlind.exe etwti list
```

Walk: `EtwpDebuggerData (+0x18)` → silo → `EtwpGuidHashTable[bucket 29]` → scan chain for `_ETW_GUID_ENTRY` with `Guid.Data1 == 0xF4E1897C`. Prints `ProviderEnableInfo (+0x060)` and all 8 per-session slots at `EnableInfo (+0x080, step +0x020)`.

Bucket 29 is fixed by the TI GUID hash regardless of build. The hash table offset in the silo is resolved directly from `_ETW_SILODRIVERSTATE` via PDB by `Offset_Resolver` and stored in `config.txt`.

---

### `etwti disable`

Disables ETW-TI kernel-side, stopping telemetry for: `ALLOCVM`, `MAPVIEW`, `READVM`, `WRITEVM`, `PROTECTVM`, `QUEUEUSERAPC`, `SETTHREADCONTEXT`.

```
EDRBlind.exe etwti disable
```

Zeroes `ProviderEnableInfo.IsEnabled (+0x060)` and all 8 `EnableInfo[].IsEnabled (+0x080..+0x160)` slots.

---

### `ppl list`

Lists all PPL-protected processes with their protection byte decoded.

```
EDRBlind.exe ppl list
```

Walks the `EPROCESS` list from `PsInitialSystemProcess` via `ActiveProcessLinks`. For each entry reads `_PS_PROTECTION` (1 byte, packed: bits 0–2 = Type, bits 4–7 = Signer).

| Type | Meaning |
|------|---------|
| 1 | PPL (Protected Process Light) |
| 2 | PP (Protected Process) |

| Signer | Examples |
|--------|---------|
| Antimalware (3) | MpDefenderCore, MsMpEng |
| Lsa (4) | lsass (RunAsPPL) |
| Windows (5) | svchost |
| WinTcb (6) | csrss, services |
| WinSystem (7) | System, Registry, MemCompression |

---

### `ppl delete <process.exe> [...]`

Strips PPL from the named process(es) by zeroing `_PS_PROTECTION`.

```
EDRBlind.exe ppl delete MsMpEng.exe
```

Uses `kwrite8` (read-modify-write on the containing aligned DWORD) since `Protection` is not guaranteed DWORD-aligned. Once stripped, the process can be opened and terminated with standard Win32 APIs.

---

## Quick Start

```bat
REM 1. Build and load driver (run from the tool directory as Administrator)
build.bat

REM 2. Resolve kernel offsets for this boot
Offset_Resolver.exe

REM 3. Use EDRBlind
EDRBlind.exe callbacks list
EDRBlind.exe etwti list
EDRBlind.exe ppl list

REM 4. To blind Defender
EDRBlind.exe callbacks delete WdFilter.sys
EDRBlind.exe etwti disable
EDRBlind.exe ppl delete MsMpEng.exe MpDefenderCore
```

---

## Requirements

- Windows 10 / 11 x64
- Administrator (UAC prompt triggered automatically)
- `RTCore64.sys` loadable (blocked on systems with HVCI or the Microsoft Vulnerable Driver Blocklist enforced)
- `dbghelp.dll` + `symsrv.dll` in the same directory as `Offset_Resolver.exe`
- Internet on first run (downloads `ntkrnlmp.pdb`); subsequent runs use the local cache at `C:\Symbols\`

---

## Disclaimer

For authorized security research, red team engagements, and EDR testing only. Do not use on systems you do not own or have explicit written permission to test.
