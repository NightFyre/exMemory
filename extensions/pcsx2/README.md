# pcsx2Memory
`pcsx2Memory` is a C++ extension class offering specialized functionality for memory operations on the PCSX2 Emulator process. This extension provides a streamlined means of reading, writing, and scanning PlayStation 2 emulated memory, as well as managing PCSX2 process and module information. `pcsx2Memory` retains all base class functionality of `exMemory`, ensuring flexibility and reuse for general memory operations.

## Features
- **PCSX2-Specific Enhancements**:
  - Simplifies interaction with PCSX2's exported memory addresses.
  - Provides tools for resolving PlayStation 2 memory addresses relative to PCSX2's EE, IOP & VU memory bases.
- **Memory Operations**:
  - Read, write, and scan emulated memory regions with ease.
  - Handle multi-level pointers and address offsets efficiently.
- **Process Management**:
  - Retrieve PCSX2 process information, including module data and memory layouts.
- **Reusable Base Functionality**:
  - Includes all features of the `exMemory` base class, making it versatile for general memory interaction.

## Getting Started

### Prerequisites

### Installation

1. Clone the repository:
```bash
git clone --branch extensions https://github.com/NightFyre/exMemory.git
```
2. Include the pcsx2Memory header file in your project:
```cpp
#include "exMemory/extensions/pcsx2/pcsx2Memory.hpp"
```

## Resources
- [PCSX2](https://pcsx2.net/)
- [PCSX2 Offset Reader](https://github.com/F0bes/pcsx2_offsetreader)
- [PCSX2 2.0 Cheat Engine Script Compatibility](https://forums.pcsx2.net/Thread-PCSX2-1-7-Cheat-Engine-Script-Compatibility)