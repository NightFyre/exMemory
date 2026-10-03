# exMemory Usage

Usage examples and API reference for `exMemory`.

> `exMemory` is a single-header library. Include `exMemory.hpp` in your project before using any of the examples below.

## Contents

- [Process Attachment](#process-attachment)
- [Memory Access](#memory-access)
- [Pointer Chains](#pointer-chains)
- [Pattern Scanning](#pattern-scanning)
- [Process Enumeration](#process-enumeration)
- [Module Enumeration](#module-enumeration)
- [Process Windows](#process-windows)
- [PE Sections](#pe-sections)
- [Export Resolution](#export-resolution)
- [DLL Injection](#dll-injection)
- [Structures](#structures)
- [Enums](#enums)

---

## Process Attachment

### Instance API

The simplest way to use `exMemory` is to create an instance attached to a process:

```cpp
exMemory mem("pcsx2-qt.exe");

if (!mem.bAttached)
    return;

const auto& proc = mem.GetProcessInfo();
```

A custom access level can also be supplied:

```cpp
exMemory mem(
    "pcsx2-qt.exe",
    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
);
```

An existing instance can be attached or reattached using:

```cpp
mem.Attach(
    "pcsx2-qt.exe",
    PROCESS_ALL_ACCESS
);
```

Detach with:

```cpp
mem.Detach();
```

### Static API

The static API exposes the same underlying functionality without maintaining an `exMemory` instance:

```cpp
procInfo_t proc{};

if (exMemory::AttachEx(
    "pcsx2-qt.exe",
    &proc,
    PROCESS_ALL_ACCESS))
{
    // use proc.hProc...

    exMemory::DetachEx(proc);
}
```

---

## Memory Access

### Reading

```cpp
const int value =
    mem.Read<int>(address);
```

Structures can be read the same way:

```cpp
const auto dosHeader =
    mem.Read<IMAGE_DOS_HEADER>(address);
```

Raw memory can be read into a buffer:

```cpp
BYTE buffer[256]{};

mem.ReadMemory(
    address,
    buffer,
    sizeof(buffer)
);
```

### Writing

```cpp
mem.Write<int>(
    address,
    100
);
```

Raw memory:

```cpp
BYTE patch[] =
{
    0x90,
    0x90,
    0x90
};

mem.WriteMemory(
    address,
    patch,
    sizeof(patch)
);
```

### Protected Memory

`PatchMemory` temporarily changes the target memory protection before writing:

```cpp
mem.PatchMemory(
    address,
    patch,
    sizeof(patch)
);
```

### Strings

```cpp
std::string text;

mem.ReadString(
    address,
    text
);
```

---

## Pointer Chains

```cpp
std::vector<unsigned int> offsets =
{
    0x1C,
    0x30
};

i64_t result = 0;

mem.ReadPointerChain(
    baseAddress,
    offsets,
    &result
);
```

Static equivalent:

```cpp
exMemory::ReadPointerChainEx(
    proc.hProc,
    baseAddress,
    offsets,
    &result
);
```

---

## Pattern Scanning

Basic wildcard pattern:

```cpp
const i64_t address =
    mem.FindPattern(
        "48 8B 05 ?? ?? ?? ??"
    );
```

Apply an offset to the result:

```cpp
const i64_t address =
    mem.FindPattern(
        "E8 ?? ?? ?? ??",
        0
    );
```

Resolve the relative target of an instruction:

```cpp
const i64_t address =
    mem.FindPattern(
        "E8 ?? ?? ?? ??",
        0,
        EASM::ASM_CALL
    );
```

Supported instruction types:

```cpp
EASM::ASM_MOV
EASM::ASM_LEA
EASM::ASM_CMP
EASM::ASM_CALL
EASM::ASM_NULL
```

---

## Process Enumeration

```cpp
std::vector<procInfo_t> processes;

if (exMemory::GetActiveProcessesEx(processes))
{
    for (const auto& proc : processes)
    {
        // proc.dwPID
        // proc.mProcName
        // proc.mProcPath
        // proc.dwModuleBase
    }
}
```

Process information can also be retrieved directly:

```cpp
procInfo_t proc{};

exMemory::GetProcInfo(
    "pcsx2-qt.exe",
    &proc
);
```

---

## Module Enumeration

```cpp
std::vector<modInfo_t> modules;

exMemory::GetProcessModulesEx(
    proc.dwPID,
    modules
);
```

Find a particular module:

```cpp
modInfo_t module{};

exMemory::FindModuleEx(
    "pcsx2-qt.exe",
    "pcsx2-qt.exe",
    &module
);
```

---

## Process Windows

Enumerate every top-level window belonging to a process:

```cpp
std::vector<wndwInfo_t> windows;

exMemory::GetProcessWindowsEx(
    proc.dwPID,
    windows
);
```

Each entry contains:

```cpp
window.hWnd
window.mTitle
window.mClassName

window.mWidth
window.mHeight

window.bVisible
window.bOwned
window.bToolWindow
```

The client area can be queried with:

```cpp
LONG64 area = window.GetArea();
```

### Automatic Window Selection

`GetProcessWindowEx` attempts to select the most likely primary application window:

```cpp
HWND window =
    exMemory::GetProcessWindowEx(
        proc.dwPID
    );
```

The selector considers windows that are:

- Visible
- Unowned
- Not tool windows
- Greater than zero client width and height

When multiple windows match, the window with the largest client area is returned.

---

## PE Sections

Retrieve the address and size of a PE section:

```cpp
i64_t sectionBase = 0;
size_t sectionSize = 0;

exMemory::GetSectionHeaderAddressEx(
    proc.hProc,
    proc.dwModuleBase,
    ESECTIONHEADERS::SECTION_TEXT,
    &sectionBase,
    &sectionSize
);
```

Supported identifiers:

```cpp
ESECTIONHEADERS::SECTION_TEXT
ESECTIONHEADERS::SECTION_DATA
ESECTIONHEADERS::SECTION_RDATA
ESECTIONHEADERS::SECTION_IMPORT
ESECTIONHEADERS::SECTION_EXPORT
```

---

## Export Resolution

Resolve a symbol from the PE export table:

```cpp
i64_t address = 0;

exMemory::GetProcAddressEx(
    proc.hProc,
    proc.dwModuleBase,
    "EEMem",
    &address
);
```

The module name overload can also be used:

```cpp
exMemory::GetProcAddressEx(
    proc.hProc,
    "pcsx2-qt.exe",
    "EEMem",
    &address
);
```

---

## DLL Injection

### Instance API

```cpp
mem.LoadLibraryInject(
    "C:\\Path\\To\\Module.dll"
);
```

### Static API

```cpp
exMemory::LoadLibraryInjectorEx(
    proc.hProc,
    "C:\\Path\\To\\Module.dll"
);
```

The current implementation uses `LoadLibrary` with a remote thread.

---

## Structures

### `procInfo_t`

Stores process information including:

```cpp
bool        bAttached;
DWORD       dwAccessLevel;
HWND        hWnd;
HANDLE      hProc;
DWORD       dwPID;
i64_t       dwModuleBase;
std::string mProcName;
std::string mProcPath;
std::string mWndwTitle;
```

### `modInfo_t`

Stores module information:

```cpp
DWORD       dwPID;
i64_t       dwModuleBase;
std::string mModName;
```

### `wndwInfo_t`

Stores information about a top-level process window:

```cpp
HWND        hWnd;

std::string mTitle;
std::string mClassName;

int         mWidth;
int         mHeight;

bool        bVisible;
bool        bOwned;
bool        bToolWindow;
```

---

## Enums

### `EASM`

Used when resolving relative addresses from pattern matches:

```cpp
EASM::ASM_MOV
EASM::ASM_LEA
EASM::ASM_CMP
EASM::ASM_CALL
EASM::ASM_NULL
```

### `ESECTIONHEADERS`

Identifies supported PE sections:

```cpp
ESECTIONHEADERS::SECTION_TEXT
ESECTIONHEADERS::SECTION_DATA
ESECTIONHEADERS::SECTION_RDATA
ESECTIONHEADERS::SECTION_IMPORT
ESECTIONHEADERS::SECTION_EXPORT
ESECTIONHEADERS::SECTION_NULL
```

### `EINJECTION`

Injection type identifiers:

```cpp
EINJECTION::INJECT_LOADLIBRARY
EINJECTION::INJECT_MANUAL
EINJECTION::INJECT_NULL
```

---

## Notes

Process and module enumeration methods rely on Windows snapshots and are considerably more expensive than cached memory operations.

For frequently accessed processes, prefer maintaining an `exMemory` instance rather than repeatedly searching for and reopening the process.

The static `Ex` methods are intended for direct operations when maintaining instance state is unnecessary.

---

[Back to README](README.md)
