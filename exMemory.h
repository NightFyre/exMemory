#pragma once
#include <windows.h>
#include <memory>
#include <string>
#include <vector>

//	architechture type helpers
#ifdef _WIN64
typedef unsigned __int64  i64_t;
#else
typedef unsigned int i64_t;
#endif

struct MODULEINFO64;

//	general process information
struct PROCESSINFO64
{
	bool							bAttached;								//	set when attached to a process
	DWORD							dwAccessLevel{ 0 };						//	access rights to process ( if attached )
	HWND							hWnd{ 0 };								//	handle to process window
	HANDLE							hProc{ INVALID_HANDLE_VALUE };			//	handle to process		
	DWORD							dwPID{ 0 };								//	process id
	i64_t							dwModuleBase{ 0 };						//	module base address
	std::string						mProcName{ "" };						//	process name
	std::string						mProcPath{ "" };						//	process path
	std::string						mWndwTitle{ "" };						//	process window title
}; typedef PROCESSINFO64 procInfo_t;

struct MODULEINFO64
{
	DWORD							dwPID{ 0 };							//	owning process id
	i64_t							dwModuleBase{ 0 };					//	module base address in process
	std::string						mModName{ "" };						//	module name
}; typedef MODULEINFO64 modInfo_t;

//	assembly opcode index
enum class EASM : int
{
	ASM_MOV = 0,
	ASM_LEA,
	ASM_CMP,
	ASM_CALL,
	ASM_NULL
};

//	section headers index
enum class ESECTIONHEADERS : int
{
	SECTION_TEXT = 0,
	SECTION_DATA,
	SECTION_RDATA,
	SECTION_IMPORT,
	SECTION_EXPORT,
	SECTION_NULL
};

//	injection type index
enum class EINJECTION : int
{
	INJECT_LOADLIBRARY = 0,
	INJECT_MANUAL,
	INJECT_NULL
};

class exMemory
{
	/*//--------------------------\\
			CONSTRUCTORS 
	*/
public:	
	explicit exMemory() = default;	//	 default constructor | does nothing
	explicit exMemory(const std::string& name);	//	attaches to process with all access rights
	explicit exMemory(const std::string& name, const DWORD& dwAccess);	//	attaches to process with specified access rights
	~exMemory() noexcept;	//	destructor | detaches from process if attached

	/*//--------------------------\\
			INSTANCE MEMBERS
	*/
public:
	bool						bAttached;	//	attached to a process

private:
	procInfo_t					vmProcess;	//	attached process information
	std::vector<procInfo_t>		vmProcList;	//	active process list
	std::vector<procInfo_t>		vmModList;	//	module list for attached process

	/*//--------------------------\\
			INSTANCE METHODS
	*/
public:	//	

	/* attempts to attach to a process by name */
	bool Attach(const std::string& name, const DWORD& dwAccess = PROCESS_ALL_ACCESS);
	
	/* detaches from the attached process */
	bool Detach();

	/* verifies attached process is active & updates processinfo structure when needed */
	void update();

	/* returns the process information structure */
	const procInfo_t& GetProcessInfo() const { return vmProcess; }


public:
	/* gets an address relative to the input named module base address */
	i64_t GetAddress(const unsigned int& offset, const std::string& modName = "");

	/* reads a memory into a buffer at the specified address in the attached process
	* returns true if all bytes were read
	*/
	bool ReadMemory(const i64_t& addr, void* buffer, const DWORD& szRead);

	/* attempts to write bytes in the attached process
	* returns true if all bytes were written successfully
	*/
	bool WriteMemory(const i64_t& addr, const void* buffer, const DWORD& szWrite);

	/* reads a continguous string in at the specified address in the attached process
	* returns true if the string was successfully read
	*/
	bool ReadString(const i64_t& addr, std::string& string, const DWORD& szString = MAX_PATH);

	/* reads a chain of pointers in the attached process to find an address in memory 
	* returns the address if found
	*/
	i64_t ReadPointerChain(const i64_t& addr, std::vector<unsigned int>& offsets, i64_t* lpResult);

	/* attempts to patch a sequence of bytes in the attached process
	* returns true if successful
	*/
	bool PatchMemory(const i64_t& addr, const void* buffer, const DWORD& szWrite);

	/* attempts to find a pattern in the attached process 
	* returns the address of pattern if found
	*/
	i64_t FindPattern(const std::string& signature, i64_t* result, int padding = 0, bool isRelative = false, EASM instruction = EASM::ASM_NULL);
	

public:

	/* template read memory with szRead parameter 
	* NOTE: does not work with strings
	*/
	template<typename T>
	auto Read(i64_t addr, DWORD szRead) noexcept -> T
	{
		T result{};
		ReadMemory(addr, &result, szRead);
		return result;
	}

	/* template read memory 
	* NOTE: does not work with strings
	*/
	template<typename T>
	auto Read(i64_t addr) noexcept -> T
	{
		T result{};
		ReadMemory(addr, &result, sizeof(T));
		return result;
	}

	/* template write memory with szPatch param */
	template<typename T>
	auto Write(i64_t addr, T patch, DWORD szPatch) noexcept -> bool { return WriteMemory(addr, &patch, szPatch); }

	/* template write memory */
	template<typename T>
	auto Write(i64_t addr, T patch) noexcept -> bool { return WriteMemory(addr, &patch, sizeof(T)); }


private:

	/* helper method to determine if the current memory instance is attached to a process for handling various memory operations */
	const bool IsValidInstance() noexcept { return !bAttached || !vmProcess.bAttached || vmProcess.hProc == INVALID_HANDLE_VALUE; }


	/*//--------------------------\\
			STATIC METHODS
	*/

public:	//	methods for directly attaching to a process

	/* attempts to attach to the named process with desired access level and returns a process information structure */
	static bool AttachEx(const std::string& name, procInfo_t* lpProcess, const DWORD& dwDesiredAccess);

	/* detaches from the attached process by freeing any opened handles to free the process information structure */
	static bool DetachEx(procInfo_t& pInfo);


public:	//	methods for retrieving information on a process by name , are somewhat slow and should not be used constantly. consider caching information if needed.

	/* attempts to retrieve a process id by name 
	* utilizes FindProcessEx which iterates through ALL processes information before again searching through the procInfo list to return a match ( if any )
	*/
	static bool GetProcID(const std::string& procName, DWORD* outPID);

	/* attempts to obtain the module base address for the specified process name 
	* utilizes FindProcessEx which iterates through ALL processes information before again searching through the procInfo list to return a match ( if any )
	*/
	static bool GetModuleBaseAddress(const std::string& procName, i64_t* lpResult, const std::string& modName = "");

	/* attempts to obtain information on a process & open a handle to it 
	* utilizes FindProcessEx which iterates through ALL processes information before again searching through the procInfo list to return a match ( if any )
	*/
	static bool GetProcInfo(const std::string& name, procInfo_t* lpout);

	/* determines if the specified name exists in the active process directory 
	* utilizes FindProcessEx which iterates through ALL processes information before again searching through the procInfo list to return a match ( if any )
	*/
	static bool IsProcessRunning(const std::string& name);


public:	//	methods for obtaining info on active processes
	
	/* obtains a list of all active processes on the machine that contains basic information on a process without requiring a handle */
	static bool GetActiveProcessesEx(std::vector<procInfo_t>& procList);

	/* obtains a list of all modules loaded in the attached process */
	static bool GetProcessModulesEx(const DWORD& dwPID, std::vector< modInfo_t>& moduleList);

	/* gets info on a process by name , can be extended to attach to the process if found 
	* utilizes GetActiveProcesses method which is somewhat slow as it obtains ALL processes before returning
	*/
	static bool FindProcessEx(const std::string& procName, procInfo_t* procInfo, const bool& bAttach, const DWORD& dwDesiredAccess);

	/* attempts to find a module by name located in the attached process and returns it's base address */
	static bool FindModuleEx(const std::string& procName, const std::string& modName, modInfo_t* lpResult);

public:	//	basic memory operations

	/* attempts to read memory at the specified address from the target process */
	static bool ReadMemoryEx(const HANDLE& hProc, const i64_t& addr, void* buffer, size_t szRead);

	/* attempts to write bytes to the specified address in memory from the target process */
	static bool WriteMemoryEx(const HANDLE& hProc, const i64_t& addr, LPVOID buffer, DWORD szWrite);

	/* attempts to read a string at the specified address in memory from the target process */
	static bool ReadStringEx(const HANDLE& hProc, const i64_t& addr, const size_t& szString, std::string* lpResult);

	/* attempts to return an address located in memory via chain of offsets */
	static bool ReadPointerChainEx(const HANDLE& hProc, const i64_t& addr, const std::vector<unsigned int>& offsets, i64_t* lpResult);

	/* attempts to patch a sequence of bytes in the target process */
	static bool PatchMemoryEx(const HANDLE& hProc, const i64_t& addr, const void* buffer, const DWORD& szWrite);

public:	//	advanced methods for obtaining information on a process which requires a handle

	/* attempts to find a module by name located in the attached process and returns it's base address */
	static bool GetModuleAddressEx(const HANDLE& hProc, const std::string& moduleName, i64_t* lpResult);

	/* attempts to return the address of a section header by index */
	static bool GetSectionHeaderAddressEx(const HANDLE& hProc, const std::string& moduleName, const ESECTIONHEADERS& section, i64_t* lpResult, size_t* szImage);
	static bool GetSectionHeaderAddressEx(const HANDLE& hProc, const i64_t& dwModule, const ESECTIONHEADERS& section, i64_t* lpResult, size_t* szImage);

	/* attempts to return an address located in memory via pattern scan. can be extended to extract bytes from an instruction */
	static bool FindPatternEx(const HANDLE& hProc, const std::string& moduleName, const std::string& signature, i64_t* lpResult, int padding, bool isRelative, EASM instruction);
	static bool FindPatternEx(const HANDLE& hProc, const i64_t& dwModule, const std::string& signature, i64_t* lpResult, int padding, bool isRelative, EASM instruction);
	
	/* attempts to find an exported function by name and return the it's rva */
	static bool GetProcAddressEx(const HANDLE& hProc, const std::string& moduleName, const std::string& fnName, i64_t* lpResult);
	static bool GetProcAddressEx(const HANDLE& hProc, const i64_t& dwModule, const std::string& fnName, i64_t* lpResult);


public:	//	injection operations 

	/* injects a module (from disk) into the target process using LoadLibrary */
	static bool LoadLibraryInjectorEx(const HANDLE& hProc, const std::string& dllPath);


public:	//	template methods

	/* template read memory with szRead parameter 
	* NOTE: does not work with strings
	*/
	template<typename T>
	static auto ReadEx(const HANDLE& hProc, const i64_t& addr, DWORD szRead) noexcept -> T
	{
		T result{};
		ReadMemoryEx(hProc, addr, &result, szRead);
		return result;
	}

	/* template read memory
	* NOTE: does not work with strings
	*/
	template<typename T>
	static auto ReadEx(const HANDLE& hProc, const i64_t& addr) noexcept -> T
	{
		T result{};
		ReadMemoryEx(hProc, addr, &result, sizeof(T));
		return result;
	}

	/* template write memory with szPatch param */
	template<typename T>
	static auto WriteEx(const HANDLE& hProc, const i64_t& addr, T patch, DWORD szPatch) noexcept -> bool { return WriteMemoryEx(hProc, addr, &patch, szPatch); }

	/* template write memory */
	template<typename T>
	static auto WriteEx(const HANDLE& hProc, const i64_t& addr, T patch) noexcept -> bool { return WriteMemoryEx(hProc, addr, &patch, sizeof(T)); }


private://	tools
	struct EnumWindowData
	{
		unsigned int procId;
		HWND hwnd;
	};

	/* callback for EnumWindows to find the maine process window */
	static BOOL CALLBACK GetProcWindowEx(HWND handle, LPARAM lParam);
};

