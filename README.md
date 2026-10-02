# EDRKiller

A BYOVD (Bring Your Own Vulnerable Driver) post-exploitation tool that tampers with Windows kernel structures to blind EDR/AV products. It abuses the **RTCore64** vulnerable driver to gain arbitrary kernel read/write primitives, then targets three defensive mechanisms:

- **Kernel notify callbacks** — used by EDRs to monitor process creation, thread creation, and image loads
- **Object callbacks** — used by EDRs to intercept process/thread handle operations
- **Registry callbacks** — used by EDRs to monitor registry activity
- **ETW Threat Intelligence (ETW-TI)** — kernel telemetry source used by many security products
- **PPL (Protected Process Light)** — protection that prevents tampering with security processes

---

## Requirements

- Windows 10 / Windows 11 (x64)
- Administrator privileges
- `RTCore64.sys` loaded as a kernel driver
- `dbghelp.dll` and `symsrv.dll` in the same directory (for PDB symbol resolution)
- Internet access on first run (downloads `ntoskrnl.pdb` from Microsoft symbol server)

---

## How It Works

On startup, `demo.exe`:

1. **Resolves kernel symbols** — loads `ntoskrnl.pdb` via `dbghelp.dll` to find the runtime addresses of key kernel globals (`PspCreateProcessNotifyRoutine`, `ObTypeIndexTable`, `CallbackListHead`, `EtwpDebuggerData`, etc.) and `_EPROCESS` field offsets. This is done fully dynamically so the tool works across kernel versions without hardcoded offsets.

2. **Opens the RTCore64 device** — communicates with the loaded vulnerable driver via `DeviceIoControl` using two IOCTLs:
   - `0x80002048` — read up to 4 bytes from any kernel address
   - `0x8000204C` — write up to 4 bytes to any kernel address

3. **Executes the requested command** using those primitives.

---

## Usage

```
demo.exe <command> <subcommand> [targets...]
```

---

## Commands

### `callbacks list`

Lists all registered kernel notify callbacks and object callbacks.

```
demo.exe callbacks list
```

Walks and prints:
- `PspCreateProcessNotifyRoutine` — process creation callbacks (up to 64 slots)
- `PspCreateThreadNotifyRoutine` — thread creation callbacks
- `PspLoadImageNotifyRoutine` — image load callbacks
- `ObCallbacks` on Process (type index 7) and Thread (type index 8) object types
- `CallbackListHead` — registry callbacks

Each entry shows the slot/node address, callback function pointer, and the owning driver name (resolved by comparing the function address against the loaded driver base address list).

---

### `callbacks delete <driver.sys> [driver2.sys ...]`

Removes all callbacks registered by the specified driver(s).

```
demo.exe callbacks delete WdFilter.sys MpKsl.sys
```

- **Process/Thread/ImageLoad callbacks**: zeroes the slot in the notify array, effectively removing the callback.
- **Object callbacks**: writes `0` to the `Active` field of the `CALLBACK_ENTRY_ITEM`, disabling the pre/post operation handlers.
- **Registry callbacks**: unlinks the node from the doubly-linked `CallbackListHead` list by rewiring `FLINK`/`BLINK` pointers.

Driver names are matched case-insensitively against the owning driver of each callback's function pointer.

---

### `etwti list`

Lists the ETW Threat Intelligence provider state.

```
demo.exe etwti list
```

Walks `EtwpDebuggerData` → silo pointer → `EtwpGuidHashTable` bucket 29 to find the `Microsoft-Windows-Threat-Intelligence` provider entry (identified by GUID `Data1 = 0xF4E1897C`). Prints:

- Provider entry address
- `ProviderEnabled` flag
- Active logger slots (logger ID for each enabled slot)

---

### `etwti disable`

Disables the ETW-TI provider kernel-side.

```
demo.exe etwti disable
```

Zeroes the `ProviderEnabled` field and all 8 logger slots in the provider entry. This prevents the kernel from emitting ETW-TI events (e.g. `KERNEL_THREATINT_TASK_ALLOCVM`, `PROTECT_VM`, `ReadVM`) that many EDRs rely on for memory-operation telemetry.

---

### `ppl list`

Lists all PPL-protected processes.

```
demo.exe ppl list
```

Walks the `EPROCESS` list starting from `PsInitialSystemProcess`, reads the `_PS_PROTECTION` byte from each process, and prints processes where the protection byte is non-zero with their type and signer level.

Protection types: `PPL` (1), `Protected` (2)  
Signer levels: `Authenticode`, `CodeGen`, `Antimalware`, `Lsa`, `Windows`, `WinTcb`, `WinSystem`, `App`

---

### `ppl delete <process.exe> [process2.exe ...]`

Strips PPL protection from the specified process(es).

```
demo.exe ppl delete MsMpEng.exe SenseIR.exe
```

Finds each named process in the `EPROCESS` list and overwrites its `_PS_PROTECTION` byte with `0x00` using a read-modify-write on the containing aligned DWORD (since the field is not guaranteed to be DWORD-aligned). Once stripped, the process can be opened and terminated with standard APIs.

---

## Files

| File | Description |
|------|-------------|
| `demo.c` | Full source code |
| `demo.exe` | Compiled x64 binary |
| `RTCore64.sys` | Vulnerable MSI driver (BYOVD primitive) |
| `dbghelp.dll` | Debug help library for PDB parsing |
| `symsrv.dll` | Symbol server client (downloads PDBs from Microsoft) |

---

## Disclaimer

For authorized security research, red team engagements, and EDR testing only. Do not use on systems you do not own or have explicit written permission to test.
