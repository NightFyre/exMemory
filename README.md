# exMemory

`exMemory` is a lightweight, single-header C++ utility for interacting with external processes on Windows.

It provides both instance-based and static interfaces for process attachment, memory access, process and module enumeration, window discovery, pattern scanning, PE inspection, export resolution, and basic DLL injection.

## Features

- Single-header implementation
- Process attachment and management
- Read and write external process memory
- String and multi-level pointer chain support
- Protected memory patching
- Process and module enumeration
- Process window enumeration and automatic window selection
- Pattern scanning with wildcard support
- Relative address resolution for common x64 instructions
- PE section inspection
- Export table resolution
- LoadLibrary DLL injection
- Instance-based and static APIs

## Getting Started

### Requirements

- Windows
- C++11 or newer
- Windows API
- MSVC recommended

### Installation

Clone the repository:

```bash
git clone https://github.com/NightFyre/exMemory.git
```

Include the header:

```cpp
#include "exMemory.hpp"
```

No additional source files are required.

## Quick Example

```cpp
#include "exMemory.hpp"

int main()
{
    exMemory mem("pcsx2-qt.exe");

    if (!mem.bAttached)
        return 1;

    const auto& proc = mem.GetProcessInfo();

    const auto dosHeader =
        mem.Read<IMAGE_DOS_HEADER>(proc.dwModuleBase);

    return 0;
}
```

For usage examples and API documentation, see **[USAGE.md](USAGE.md)**.

## API Overview

`exMemory` provides two ways to interact with a process.

### Instance API

Designed for applications that maintain an active process connection:

```cpp
exMemory mem("pcsx2-qt.exe");

auto value = mem.Read<int>(address);

mem.Write<int>(address, value);
```

### Static API

The `Ex` methods provide direct operations without requiring an `exMemory` instance:

```cpp
procInfo_t proc{};			// process info structure ( pid , handle , module base address . . . )

if (exMemory::AttachEx(
    "pcsx2-qt.exe",			// process name
    &proc,					// handle to process info
    PROCESS_ALL_ACCESS		// desired access level
))
{
    auto value = exMemory::ReadEx<int>(proc.hProc, address);

    exMemory::DetachEx(proc);
}
```

## Core Components

| Type | Description |
| --- | --- |
| `exMemory` | Main external process interface |
| `procInfo_t` | Process information and attachment state |
| `modInfo_t` | Loaded module information |
| `wndwInfo_t` | Process window information |
| `EASM` | Instruction types used for relative address resolution |
| `ESECTIONHEADERS` | Supported PE section identifiers |
| `EINJECTION` | Injection method identifiers |

## Documentation

See **[USAGE.md](USAGE.md)** for examples covering:

- Process attachment
- Reading and writing memory
- Pointer chains
- Pattern scanning
- Process and module enumeration
- Process window enumeration
- PE section walking
- Export resolution
- DLL injection

## Potential Future Additions

- Improved error reporting
- Additional DLL injection methods
- Code cave utilities
- Module dumping

## Resources

- [Windows Process Enumeration](https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
- [Windows Memory Management](https://learn.microsoft.com/en-us/windows/win32/memory/about-memory-management)
- [Virtual Memory Functions](https://learn.microsoft.com/en-us/windows/win32/memory/virtual-memory-functions)
- [EnumWindows](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows)
- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

---

### NightFyre Frameworks

`exMemory` is provided as a lightweight utility for external process tooling and research.
