# exMemory
`exMemory` is a C++ utility class designed for advanced memory manipulation tasks on external processes. It supports reading, writing, and patching memory, as well as managing process and module information. The class offers both static and instance-based operations for maximum flexibility.

## Features
- Attach and detach from processes.
- Read and write memory (including pointer chains and strings).
- Patch memory with custom byte sequences.
- Find and manipulate modules and sections in a process.
- Pattern scanning with optional instruction-based offsets.
- Retrieve process and module information.
- Static methods for direct operations without maintaining an instance.

---

## Getting Started

### Prerequisites

- Windows operating system
- A modern C++ compiler (e.g., MSVC)
- `Windows.h` header for Windows API

### Installation

1. Clone the repository:
```bash
   git clone https://github.com/yourusername/exMemory.git
```
2. Include the exMemory.h file in your project:
```cpp
#include "exMemory.h"
```

## Usage
1. 
You can use `exMemory` in two ways: instance-based or through static methods.

**Instance-Based Example**
```cpp
#include "exMemory.h"

int main() 
{
    exMemory mem = exMemory("pcsx2-qt.exe", PROCESS_ALL_ACCESS);    //  attaches to the named process if found
    const auto& pInfo = mem.GetProcessInfo();   //  basic process information is obtained during the attach procedure
    
    int value = memory.Read<int>(pInfo.dwModuleBase + 0x12345678);  //  read 4 bytes from the target process at the input address
    
    memory.Detach();    //  detach and free any resources
    
    return 0;
}
```

**Static Method Example**
```cpp
#include "exMemory.h"

int main() 
{
    procInfo_t proc;
    if (exMemory::AttachEx("pcsx2-qt.exe", &proc, PROCESS_ALL_ACCESS))
    {
        int value = exMemory::ReadEx<int>(pInfo.hProc, pInfo.dwModuleBase + 0x12345678); 
        
        exMemory::DetachEx(proc);
    }
    
    return 0;
}
```

2. Key Methods

**Instance Methods**
- Attach/Detach
```cpp
bool Attach(const std::string& name, const DWORD& dwAccess = PROCESS_ALL_ACCESS);
bool Detach();
```

- Read/Write Memory
```cpp
template<typename T>
T Read(i64_t addr);

template<typename T>
bool Write(i64_t addr, T value);
```

- Pattern Scanning
```cpp
i64_t FindPattern(const std::string& signature, i64_t* result, int padding = 0, bool isRelative = false, EASM instruction = EASM::ASM_NULL);
```

**Static Methods**
- Attach/Detach
```cpp
static bool AttachEx(const std::string& name, procInfo_t* lpProcess, const DWORD& dwDesiredAccess);
static bool DetachEx(procInfo_t& pInfo);
```

- Direct Memory Operations
```cpp
static bool ReadMemoryEx(const HANDLE& hProc, const i64_t& addr, void* buffer, size_t szRead);
static bool WriteMemoryEx(const HANDLE& hProc, const i64_t& addr, LPVOID buffer, DWORD szWrite);
static bool PatchMemoryEx(const HANDLE& hProc, const i64_t& addr, const void* buffer, const DWORD& szWrite);
```

### Advanced Features
**Pattern Scanning**
Find memory patterns with custom instructions and offsets:
```cpp
i64_t address = memory.FindPattern("90 90 ?? ?? E8 ?? ?? ?? ??", nullptr, 0, true, EASM::ASM_CALL);
```

**Pointer Chains**
Resolve multi-level pointer chains:
```cpp
//	get process information for pcsx2-qt.exe
//  remember that Reading & writing process memory requires a handle to the process 
procInfo_t proc;
if (exMemory::AttachEx("pcsx2-qt.exe", &proc, PROCESS_ALL_ACCESS))
{
	i64_t result;
	std::vector<unsigned int> offsets = { 0x10, 0x20, 0x30 };
	exMemory::ReadPointerChainEx(proc.hProc, 0x12345678, offsets, &result);
	//	...
	exMemory::DetachEx(proc);   //  free resources and close any opened handles 
}
```

**Section Walking**
Get the base address of a section in a processes module
```cpp
//	get process information for pcsx2-qt.exe
//  remember that Reading & writing process memory requires a handle to the process 
procInfo_t proc;
if (exMemory::AttachEx("pcsx2-qt.exe", &proc, PROCESS_ALL_ACCESS))
{
	size_t szSection = 0;
	i64_t SectionHeader = 0;
	exMemory::GetSectionHeaderAddressEx(pInfo.hProc, "pcsx2-qt.exe", ESECTIONHEADERS::SECTION_TEXT, &SectionHeader, &szSection);
	//	...
	exMemory::DetachEx(proc);   //  free resources and close any opened handles 
}

```

**Resolve Export Table Entries**
Retrieve the address of an exported function
```cpp
//	get process information for pcsx2-qt.exe
//  remember that Reading & writing process memory requires a handle to the process 
procInfo_t proc;
if (exMemory::AttachEx("pcsx2-qt.exe", &proc, PROCESS_ALL_ACCESS))
{
	exMemory::GetProcAddressEx(proc.hProc, "pcsx2-qt.exe", "EEmem", &EEmem);	//	get proc address of "EEmem" exported function from notepad.exe module
	//	...
	exMemory::DetachEx(proc);   //  free resources and close any opened handles 
}
```

### Enums and Structures
**Enums**
- EASM: Assembly instruction types (e.g., ASM_MOV, ASM_CALL).
- ESECTIONHEADERS: Section headers in a PE file (e.g., .text, .data).
- EINJECTION: Injection types (e.g., LOADLIBRARY, MANUAL).

### Structures
- procInfo_t: Represents process information (ID, handle, base address, etc.).
- modInfo_t: Represents module information (base address, name, etc.).

**Performance Considerations**
- Instance methods are optimized for scenarios where a process is frequently accessed.
- Static methods are ideal for one-off operations without maintaining a persistent state.
- Avoid repeated calls to slow methods like GetActiveProcessesEx unless caching results.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for bug reports and feature suggestions.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- Windows API documentation
- various community resources
