#include <exMemory/exMemory.hpp>

struct pcsx2PROCESSINFO : public PROCESSINFO64
{
	i64_t dwEEBase{ 0 };		//	
	i64_t dwIOPBase{ 0 };		//	
	i64_t dwVUBase{ 0 };		//	
}; typedef pcsx2PROCESSINFO pcsx2Info_t;

enum EPCSX2MEMORY : int
{
	EPSX_EE = 0,
	EPSX_IOP,
	EPSX_VU
};

class pcsx2Memory : public exMemory
{
	/*//--------------------------\\
			CONSTRUCTORS
	*/
public:
	explicit pcsx2Memory();
	explicit pcsx2Memory(const std::string& name, EPCSX2MEMORY mem = EPSX_EE);
	explicit pcsx2Memory(const std::string& name, const DWORD& dwAccess, EPCSX2MEMORY mem = EPSX_EE);

	/*//--------------------------\\
			INSTANCE MEMBERS
	*/
protected:
	pcsx2Info_t pcxInfo;					//	pcsx2 process information
	EPCSX2MEMORY eMemory{ EPSX_EE };		//	selected memory region for memory operations


	/*//--------------------------\\
			INSTANCE METHODS
	*/
public:	//	process attachment & detachment
	/* attaches to the named pcsx2 process and retrieves the base addresses for EE, IOP & VU memory
	*/
	inline bool Attach(const std::string& name, const DWORD& dwAccess) override;

	/* detaches from pcsx2 and frees any allocated memory */
	inline bool Detach() override;

	/* checks if the pcsx2 process is still running and updates class member information */
	inline void update() override;

public://	process information retrieval
	/* obtains pcsx2 process information structure */
	inline const pcsx2Info_t& psxGetInfo() const { return pcxInfo; }

	/* obtains EEMemory Virtual Address */
	inline const i64_t& psxGetEEMemory() const { return pcxInfo.dwEEBase; }

	/* obtains IOP Virtual Address */
	inline const i64_t& psxGetIOPMemory() const { return pcxInfo.dwIOPBase; }

	/* obtains VU Virtual Address */
	inline const i64_t& psxGetVUMemory() const { return pcxInfo.dwVUBase; }

public:	//	basic memory operations
	/* gets an address in memory offset from EEmemory */
	inline i64_t psxGetAddress(const unsigned __int32& offset);

	/* reads into a buffer at the specified offset relative to EEMmeory
	* returns true if all bytes were read
	*/
	inline bool psxReadMemory(const unsigned __int32& offset, void* buffer, const DWORD& szRead);
	
	/*  */
	inline std::string psxReadString(const unsigned __int32& offset, const size_t& szString = MAX_PATH);

	/* reads a chain of pointers at the specified offset relative to EEMmeory to find an address in memory */
	inline i64_t psxReadPointerChain(const unsigned __int32& offset, const std::vector<unsigned __int32>& offsets);

	/* writes a sequence of bytes to the specified offset relative to EEMmeory
	* returns true if all bytes were written successfully
	*/
	inline bool psxWriteMemory(const unsigned __int32& offset, const void* buffer, const DWORD& szWrite);

	/* writes a sequence of bytes to the specified offset relative to EEMmeory, adjusting the protection level if needed
	* returns true if patch was successful
	*/
	inline bool psxPatchMemory(const unsigned __int32& offset, const void* buffer, const DWORD& szWrite);


	/*//--------------------------\\
			TEMPLATE METHODS
	*/
public:
	/**/
	template<typename T>
	auto psxRead(const __int32& offset) noexcept -> T
	{
		T result{};
		psxReadMemory(offset, &result, sizeof(T));
		return result;
	}

	/**/
	template<typename T>
	auto psxReadPTR(const __int32& offset) noexcept -> T
	{
		T result{};
		i64_t pBuf = 0;
		if (psxReadMemory(offset, &pBuf, sizeof(pBuf)) && pBuf > 0)
			psxReadMemory(pBuf, &result, sizeof(T));
		return result;
	}

	/**/
	template <typename T>
	auto psxReadChain(const unsigned __int32& offset, const std::vector<unsigned __int32>& offsets) noexcept -> T
	{
		T result{};
		i64_t addr = psxReadPointerChain(offset, offsets);
		if (addr)
			ReadMemory(addr, &result, sizeof(T));
		return result;
	}

	/**/
	template<typename T>
	auto psxWrite(const __int32& offset, const T& patch) noexcept -> bool
	{
		return psxWriteMemory(offset, &patch, sizeof(T));
	}

	/**/
	template<typename T>
	auto psxWritePTR(const __int32& offset, const T& patch) noexcept -> bool
	{
		i64_t pBuf = 0;
		if (!psxReadMemory(offset, &pBuf, sizeof(pBuf)) && pBuf > 0)
			return false;

		return psxWriteMemory(pBuf, &patch, sizeof(T));
	}

	/**/
	template<typename T> 
	auto psxWriteChain(const unsigned __int32& offset, const std::vector<unsigned __int32>& offsets, const T& patch) noexcept -> bool
	{
		i64_t addr = psxReadPointerChain(offset, offsets);
		if (!addr)
			return false;

		return WriteMemory(addr, &patch, sizeof(T));
	}


	/*//--------------------------\\
			STATIC METHODS
	*/
public:

	/*//--------------------------\\
			TOOL METHODS
	*/
protected:
	/* resets EE before it tries to execute any code, if pending.
	* function: https://github.com/PCSX2/pcsx2/blob/f2c796bcc528b0366b1dec4fc471414efab9b1db/pcsx2/x86/ix86-32/iR5900.cpp#L650
	* flag: https://github.com/PCSX2/pcsx2/blob/f2c796bcc528b0366b1dec4fc471414efab9b1db/pcsx2/x86/ix86-32/iR5900.cpp#L43
	*/
	inline bool recResetEE();
};

pcsx2Memory::pcsx2Memory() : exMemory()
{
	bAttached = Attach("pcsx2-qt.exe", PROCESS_ALL_ACCESS);
	eMemory = EPSX_EE;
}

pcsx2Memory::pcsx2Memory(const std::string& name, EPCSX2MEMORY mem) : exMemory(name)
{
	bAttached = Attach(name, PROCESS_ALL_ACCESS);
	eMemory = mem;
}

pcsx2Memory::pcsx2Memory(const std::string& name, const DWORD& dwAccess, EPCSX2MEMORY mem) : exMemory(name, dwAccess)
{
	bAttached = Attach(name, dwAccess);
	eMemory = mem;
}

bool pcsx2Memory::Attach(const std::string& name, const DWORD& dwAccess)
{
	procInfo_t proc;
	if (!AttachEx(name, &proc, dwAccess))
		return false;

	vmProcess = proc;

	i64_t eemem = 0;
	if (!GetProcAddressEx(proc.hProc, proc.dwModuleBase, "EEMem", &eemem))
		return false;

	i64_t iopmem = 0;
	if (!GetProcAddressEx(proc.hProc, proc.dwModuleBase, "IOPMem", &iopmem))
		return false;

	i64_t vumem = 0;
	if (!GetProcAddressEx(proc.hProc, proc.dwModuleBase, "VUMem", &vumem))
		return false;

	pcsx2Info_t pcx = reinterpret_cast<pcsx2Info_t&>(vmProcess);
	pcx.dwEEBase = ReadEx<i64_t>(pcx.hProc, eemem);
	pcx.dwIOPBase = ReadEx<i64_t>(pcx.hProc, iopmem);
	pcx.dwVUBase = ReadEx<i64_t>(pcx.hProc, vumem);
	pcxInfo = pcx;

	return pcxInfo.bAttached;
}

bool pcsx2Memory::Detach()
{
	bool result = DetachEx(vmProcess);

	pcxInfo = pcsx2Info_t();

	return result;
}

void pcsx2Memory::update()
{
	const bool& bAttched = pcxInfo.bAttached;	//	is instance attached to a process ?

	//	check if attached process is running
	//	if (!IsProcessRunning(pcxInfo.mProcName))
	//	{
	//		Detach();	//	close handles and free resources if not already done ( safe to call multiple times if nothing is attached )
	//		return;
	//	}

	//	attached process is running, update process information


	//  attempt to get main process window
	EnumWindowData eDat;
	eDat.procId = pcxInfo.dwPID;
	if (EnumWindows(GetProcWindowEx, reinterpret_cast<LPARAM>(&eDat)))
		pcxInfo.hWnd = eDat.hwnd;

	//  Get window title
	char buffer[MAX_PATH];
	if (pcxInfo.hWnd && GetWindowTextA(pcxInfo.hWnd, buffer, MAX_PATH))
		pcxInfo.mWndwTitle = std::string(buffer);

	vmProcess = reinterpret_cast<procInfo_t&>(pcxInfo);	//	update vmProcess
}

i64_t pcsx2Memory::psxGetAddress(const unsigned __int32& offset)
{
	i64_t result = 0;
	
	switch (eMemory)
	{
	case EPCSX2MEMORY::EPSX_EE: result = pcxInfo.dwEEBase + offset; break;
	case EPCSX2MEMORY::EPSX_IOP: result = pcxInfo.dwIOPBase + offset; break;
	case EPCSX2MEMORY::EPSX_VU: result = pcxInfo.dwVUBase + offset; break;
		default: 
			return 0;
	}

	return result;
}

bool pcsx2Memory::psxReadMemory(const unsigned __int32& offset, void* buffer, const DWORD& szRead)
{
	const i64_t& addr = psxGetAddress(offset);
	if (!addr)
		return false;

	return ReadMemory(addr, buffer, szRead);
}

std::string pcsx2Memory::psxReadString(const unsigned __int32& offset, const size_t& szString)
{
	std::string result;
	const i64_t& addr = psxGetAddress(offset);
	if (!addr)
		return result;

	ReadString(addr, result, szString);
	return result;
}

i64_t pcsx2Memory::psxReadPointerChain(const unsigned __int32& offset, const std::vector<unsigned __int32>& offsets)
{
	i64_t addr = psxGetAddress(offset);
	if (!addr)
		return 0;

	for (int i = 0; i < offsets.size(); ++i)
	{
		addr = psxGetAddress(Read<__int32>(addr));
		addr += offsets[i];
	}

	return addr;
}

bool pcsx2Memory::psxWriteMemory(const unsigned __int32& offset, const void* buffer, const DWORD& szWrite)
{
	const i64_t& addr = psxGetAddress(offset);
	if (!addr)
		return false;
	return WriteMemory(addr, LPVOID(buffer), szWrite);
}

bool pcsx2Memory::psxPatchMemory(const unsigned __int32& offset, const void* buffer, const DWORD& szWrite)
{
	const i64_t& addr = psxGetAddress(offset);
	if (!addr)
		return false;

	//	store original protection & set new protection
	DWORD oldprotect;
	if (!VirtualProtectEx(pcxInfo.hProc, LPVOID(addr), szWrite, PAGE_READWRITE, &oldprotect))
		return false;

	//	write patch to memory
	bool result = WriteProcessMemory(pcxInfo.hProc, LPVOID(addr), buffer, szWrite, nullptr);
	
	//	restore memory protection
	if (!VirtualProtectEx(pcxInfo.hProc, LPVOID(addr), szWrite, oldprotect, &oldprotect))
		return false;	//	failed to restore memory protection ; @TODO: restore patch ?

	//	reset the instruction cache
	return recResetEE();
}

bool pcsx2Memory::recResetEE()
{
	/* recRestEE is a boolean flag in the pcsx2-qt.exe process that is used to reset EE before it tries to execute any code, if pending.
	* flag: https://github.com/PCSX2/pcsx2/blob/f2c796bcc528b0366b1dec4fc471414efab9b1db/pcsx2/x86/ix86-32/iR5900.cpp#L43
	*/
	static i64_t recNeedsReset = 0;
	if (!recNeedsReset)
	{
		//	pcsx2-qt.exe.text+41202D - C6 05 FC6A8A03 01     - mov byte ptr [pcsx2-qt.exe+3CB9B30],01
		const auto addr = FindPattern("C6 05 ? ? ? ? ? C6 05 ? ? ? ? ? 80 3D ? ? ? ? ? 74");
		if (!addr)
			return false;

		//	rip the offset from the instruction
		const unsigned int offset = ReadEx<int>(pcxInfo.hProc, addr + 0x2);
		
		//	get the relative address based on the sum of address , offset & instruction size 
		recNeedsReset = (addr + offset) + 0x7;	//	0x7 = size of instruction
	}

	//	set flag to trigger a reset
	return Write<bool>(recNeedsReset, 0x1);
}