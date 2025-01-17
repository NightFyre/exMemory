#include "exMemory.h"

#include <TlHelp32.h>
#include <Psapi.h>

#include <StringHelper.h>

exMemory::exMemory()
{

}

exMemory::exMemory(const std::string& name) 
{ 
	bAttached = Attach(name, PROCESS_ALL_ACCESS); 
}

exMemory::exMemory(const std::string& name, const DWORD& dwAccess)
{
	bAttached = Attach(name, dwAccess);
}

exMemory::~exMemory()
{
	Detach();	//	close handles and free resources
}


//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------


bool exMemory::Attach(const std::string& name, const DWORD& dwAccess)
{
	procInfo_t proc;
	if (!AttachEx(name, &proc, dwAccess))
		return false;

	vmProcess = proc;

	return vmProcess.bAttached;
}

bool exMemory::Detach()
{
	return DetachEx(vmProcess);
}

void exMemory::update()
{
	const bool& bAttched = vmProcess.bAttached;	//	is instance attached to a process ?

	//	check if attached process is running
	if (!IsProcessRunning(vmProcess.mProcName))
	{
		Detach();	//	close handles and free resources if not already done ( safe to call multiple times if nothing is attached )
		return;
	}

	//	attached process is running, update process information
}


//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------

bool exMemory::ReadMemory(const i64_t& addr, void* buffer, const DWORD& szRead)
{
	if (!IsValidInstance())
		return false;

	return ReadMemoryEx(vmProcess.hProc, addr, buffer, szRead);
}

bool exMemory::ReadString(const i64_t& addr, std::string& string, const DWORD& szString)
{
	if (!IsValidInstance())
		return false;

	return ReadStringEx(vmProcess.hProc, addr, szString, &string);
}

i64_t exMemory::ReadPointerChain(const i64_t& addr, std::vector<unsigned int>& offsets, i64_t* lpResult)
{
	if (!IsValidInstance())
		return 0;

	if (!ReadPointerChainEx(vmProcess.hProc, addr, offsets, lpResult))
		return 0;

	return *lpResult;
}

i64_t exMemory::FindPattern(const std::string& signature, i64_t* result, int padding, bool isRelative, EASM instruction)
{
	if (!IsValidInstance())
		return 0;

	if (!FindPatternEx(vmProcess.hProc, vmProcess.dwModuleBase, signature, result, padding, isRelative, instruction))
		return 0;

	return *result;
}

bool exMemory::WriteMemory(const i64_t& addr, const void* buffer, const DWORD& szWrite)
{
	if (!IsValidInstance())
		return false;

	return WriteMemoryEx(vmProcess.hProc, addr, &buffer, szWrite);
}

bool exMemory::PatchMemory(const i64_t& addr, const void* buffer, const DWORD& szWrite)
{
	if (!IsValidInstance())
		return false;

	return PatchMemoryEx(vmProcess.hProc, addr, buffer, szWrite);
}

//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------

bool exMemory::AttachEx(const std::string& name, procInfo_t* lpProcess, const DWORD& dwDesiredAccess)
{
	return FindProcessEx(name, lpProcess, true, dwDesiredAccess);
}

bool exMemory::DetachEx(procInfo_t& pInfo)
{
	bool result{ true };

	if (pInfo.bAttached && pInfo.hProc != INVALID_HANDLE_VALUE)
		CloseHandle(pInfo.hProc);	//	close handle to process

	pInfo = procInfo_t();	//	clear process information

	return result;
}

//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------

bool exMemory::GetProcID(const std::string& procName, DWORD* outPID)
{
	procInfo_t proc;
	if (!GetProcInfo(procName, &proc))
		return false;

	*outPID = proc.dwPID;

	return proc.dwPID > 0;
}

bool exMemory::GetModuleBaseAddress(const std::string& procName, i64_t* lpResult, const std::string& modName)
{
	if (!modName.empty())
	{
		modInfo_t mod;
		if (!FindModuleEx(procName, modName, &mod))
			return false;

		*lpResult = mod.dwModuleBase;

		return mod.dwModuleBase > 0;
	}

	procInfo_t proc;
	if (!GetProcInfo(procName, &proc))
		return false;

	*lpResult = proc.dwModuleBase;

	return proc.dwModuleBase > 0;
}

bool exMemory::GetProcInfo(const std::string& name, procInfo_t* lpResult)
{
	return FindProcessEx(name, lpResult, false, NULL);
}

bool exMemory::IsProcessRunning(const std::string& name)
{
	return FindProcessEx(name, nullptr, false, NULL);
}

//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------

bool exMemory::GetActiveProcessesEx(std::vector<procInfo_t>& list)
{
	//	snapshot processes
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);
	if (!Process32Next(hSnap, &procEntry))
	{
		CloseHandle(hSnap);
		return FALSE;
	}

	//  iterate through all processes
	std::vector<procInfo_t> active_process_list;
	do
	{
		const DWORD procID = procEntry.th32ProcessID;
		if (!procID)
			continue;

		//	snapshot modules
		HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, procID);
		if (modSnap == INVALID_HANDLE_VALUE)
			continue;

		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (!Module32First(modSnap, &modEntry))
		{
			CloseHandle(modSnap);
			continue;
		}

		//	 iterate through all modules
		do
		{
			//	compare module names
			if (_wcsicmp(modEntry.szModule, procEntry.szExeFile))
				continue;

			//	module found
			procInfo_t proc;
			proc.mProcName = StringHelper::ToString(procEntry.szExeFile);      //  process name
			proc.mProcPath = StringHelper::ToString(modEntry.szExePath);       //  process path
			proc.dwPID = procID;											   //  process ID
			proc.dwModuleBase = i64_t(modEntry.modBaseAddr);                   //  module base address
			
			//  push back process to list
			active_process_list.push_back(proc);

			break;  //  get next process information

		} while (Module32Next(modSnap, &modEntry));

		CloseHandle(modSnap);

	} while (Process32Next(hSnap, &procEntry));

	CloseHandle(hSnap);

	list = active_process_list;

	return list.size() > 0;
}

bool exMemory::GetProcessModulesEx(const DWORD& dwPID, std::vector<modInfo_t>& list)
{	
	//	snapshot modules
	HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, dwPID);
	if (modSnap == INVALID_HANDLE_VALUE)
		return false;

	MODULEENTRY32 modEntry;
	modEntry.dwSize = sizeof(modEntry);
	if (!Module32First(modSnap, &modEntry))
	{
		CloseHandle(modSnap);
		return false;
	}

	//	 iterate through all modules
	std::vector<modInfo_t> active_module_list;
	do
	{
		//	module found
		modInfo_t mod;
		mod.dwPID = dwPID;												   //  process ID
		mod.dwModuleBase = i64_t(modEntry.modBaseAddr);					   //  module base address
		mod.mModName = StringHelper::ToString(modEntry.szModule);		   //  module name

		//  push back module to list
		active_module_list.push_back(mod);

	} while (Module32Next(modSnap, &modEntry));

	CloseHandle(modSnap);

	list = active_module_list;

	return list.size() > 0;
}

bool exMemory::FindProcessEx(const std::string& procName, procInfo_t* procInfo, const bool& bAttach, const DWORD& dwDesiredAccess)
{
	std::vector<procInfo_t> list;
	if (!GetActiveProcessesEx(list))
		return false;

	auto it = std::find_if(
		list.begin(),
		list.end(),
		[procName](procInfo_t& p)
		{
			return p.mProcName == procName;
		}
	);

	if (it == list.end())
		return false;

	procInfo_t& proc = *it;	//	pass found procInfo reference
	
	//	attach to process ?
	if (bAttach)
	{
		proc.dwAccessLevel = dwDesiredAccess;

		//  attempt to get main process window
		EnumWindowData eDat;
		eDat.procId = proc.dwPID;
		if (EnumWindows(GetProcWindowEx, reinterpret_cast<LPARAM>(&eDat)))
			proc.hWnd = eDat.hwnd;

		//  Get window title
		char buffer[MAX_PATH];
		if (proc.hWnd && GetWindowTextA(proc.hWnd, buffer, MAX_PATH))
			proc.mWndwTitle = std::string(buffer);

		//  open handle to process
		proc.hProc = OpenProcess(proc.dwAccessLevel, false, it->dwPID);

		proc.bAttached = proc.hProc != INVALID_HANDLE_VALUE;
	}

	if (procInfo)
		*procInfo = proc;

	return true;
}

bool exMemory::FindModuleEx(const std::string& procName, const std::string& modName, modInfo_t* lpResult)
{
	const auto& proc_cmp = StringHelper::ToLower(procName);
	const auto& mod_cmp = StringHelper::ToLower(modName);
	bool bFound{ false };
	modInfo_t modInfo;

	//	snapshot processes
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);
	if (!Process32Next(hSnap, &procEntry))
	{
		CloseHandle(hSnap);
		return FALSE;
	}

	//  iterate through all processes
	do
	{
		//	compare process names
		if (StringHelper::ToLower(StringHelper::ToString(procEntry.szExeFile)) != proc_cmp)
			continue;

		//	snapshot modules
		HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, procEntry.th32ProcessID);
		if (modSnap == INVALID_HANDLE_VALUE)
			break;

		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (!Module32First(modSnap, &modEntry))
		{
			CloseHandle(modSnap);
			break;
		}

		//	 iterate through all modules
		do
		{
			//	compare module names
			if (StringHelper::ToLower(StringHelper::ToString(modEntry.szModule)) != mod_cmp)
				continue;

			//	module found
			bFound = true;

			//	get module properties
			modInfo.dwModuleBase = i64_t(modEntry.modBaseAddr);                   //  module base address
			modInfo.dwPID = procEntry.th32ProcessID;                              //  process ID
			modInfo.mModName = StringHelper::ToString(modEntry.szModule);		//  module name

			//	pass ref
			*lpResult = modInfo;

			break;

		} while (Module32Next(modSnap, &modEntry));

		CloseHandle(modSnap);

		break;

	} while (Process32Next(hSnap, &procEntry));

	CloseHandle(hSnap);

	return bFound;
}

//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------

bool exMemory::GetModuleAddressEx(const HANDLE& hProc, const std::string& moduleName, i64_t* lpResult)
{
	DWORD cbNeeded;
	HMODULE modules[1024];
	if (!EnumProcessModulesEx(hProc, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL))
		return false;
	
	const auto szModule = cbNeeded / sizeof(HMODULE);
	for (int i = 0; i < szModule; i++)
	{
		wchar_t modName[MAX_PATH];
		if (!GetModuleBaseName(hProc, modules[i], modName, sizeof(modName) / sizeof(wchar_t)))
			continue;

		if (StringHelper::ToLower(StringHelper::ToString(modName)) != moduleName)
			continue;

		*lpResult = reinterpret_cast<i64_t>(modules[i]);

		return true;
	}

	return false;
}

bool exMemory::GetProcAddressEx(const HANDLE& hProc, const std::string& moduleName, const std::string& fnName, i64_t* lpResult)
{
	i64_t dwModuleBase = 0;
	if (!GetModuleAddressEx(hProc, moduleName, &dwModuleBase) || !dwModuleBase)
		return false;

	return GetProcAddressEx(hProc, dwModuleBase, fnName, lpResult);
}

bool exMemory::GetProcAddressEx(const HANDLE& hProc, const i64_t& dwModule, const std::string& fnName, i64_t* lpResult)
{
	const auto& fnNameLower = StringHelper::ToLower(fnName);

	//	get image doe header
	const auto& image_dos_header = ReadEx<IMAGE_DOS_HEADER>(hProc, dwModule);
	if (image_dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	//	get nt headers
	const auto& image_nt_headers = ReadEx<IMAGE_NT_HEADERS>(hProc, dwModule + image_dos_header.e_lfanew);
	if (image_nt_headers.Signature != IMAGE_NT_SIGNATURE
		|| image_nt_headers.OptionalHeader.NumberOfRvaAndSizes <= 0)
		return false;

	//	get export directory
	const auto& export_directory_va = image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + dwModule;
	const auto& export_directory = ReadEx<IMAGE_EXPORT_DIRECTORY>(hProc, export_directory_va);
	if (!export_directory.AddressOfNames || !export_directory.AddressOfFunctions || !export_directory.AddressOfNameOrdinals)
		return false;

	//	get address of *
	const auto& names_va = dwModule + export_directory.AddressOfNames;
	const auto& functions_va = dwModule + export_directory.AddressOfFunctions;
	const auto& ordinals_va = dwModule + export_directory.AddressOfNameOrdinals;
	for (int i = 0; i < export_directory.NumberOfNames; i++)
	{
		//	get address of name
		const auto& name_rva = ReadEx<DWORD>(hProc, names_va + (i * 0x4));
		const auto& name_va = name_rva + dwModule;

		//	read & compare name with input string
		std::string cmp;
		if (!ReadStringEx(hProc, name_va, MAX_PATH, &cmp))
			continue;

		//	compare strings
		if (fnNameLower != StringHelper::ToLower(cmp))
			continue;

		//	get function address
		const auto& name_ordinal = ReadEx<short>(hProc, ordinals_va + (i * 0x2));				//	get ordinal at the current index
		const auto& function_rva = ReadEx<DWORD>(hProc, functions_va + (name_ordinal * 0x4));	//	get function va from the ordinal index of the functions array

		//	pass result
		*lpResult = i64_t(function_rva + dwModule);

		return true;
	}

	return false;
}

bool exMemory::GetSectionHeaderAddressEx(const HANDLE& hProc, const std::string& moduleName, const ESECTIONHEADERS& section, i64_t* lpResult, size_t* szImage)
{
	i64_t dwModuleBase = 0;
	if (!GetModuleAddressEx(hProc, moduleName, &dwModuleBase) || !dwModuleBase)
		return false;

	return GetSectionHeaderAddressEx(hProc, dwModuleBase, section, lpResult, szImage);
}

bool exMemory::GetSectionHeaderAddressEx(const HANDLE& hProc, const i64_t& dwModule, const ESECTIONHEADERS& section, i64_t* lpResult, size_t* szImage)
{
	//	get segment title
	std::string segment;
	switch (section)
	{
		case ESECTIONHEADERS::SECTION_TEXT: { segment = ".text"; break; }
		case ESECTIONHEADERS::SECTION_DATA: { segment = ".data"; break; }
		case ESECTIONHEADERS::SECTION_RDATA: { segment = ".rdata"; break; }
		case ESECTIONHEADERS::SECTION_IMPORT: { segment = ".idata"; break; }
		case ESECTIONHEADERS::SECTION_EXPORT: { segment = ".edata"; break; }
		default: return false;
	}
	if (segment.empty())	//	segment title not captured ?? 
		return false;

	//	get dos header
	const auto& image_dos_header = ReadEx<IMAGE_DOS_HEADER>(hProc, dwModule);
	if (image_dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	//	get nt headers
	/*https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64*/
	const auto& e_lfanew = dwModule + image_dos_header.e_lfanew;
	const auto& image_nt_headers = ReadEx<IMAGE_NT_HEADERS>(hProc, e_lfanew);
	if (image_nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return false;

	//	Get section
	/*https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header*/
	size_t section_size = 0;
	i64_t section_base = 0;
	const auto& image_section_header = e_lfanew + sizeof(IMAGE_NT_HEADERS);
	IMAGE_SECTION_HEADER section_headers_base = ReadEx<IMAGE_SECTION_HEADER>(hProc, image_section_header);

	/*https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header*/
	/*https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64*/
	for (int i = 0; i < image_nt_headers.FileHeader.NumberOfSections; ++i)
	{
		if (strncmp(reinterpret_cast<const char*>(section_headers_base.Name), segment.c_str(), segment.size()) != 0)
		{
			section_headers_base = ReadEx<IMAGE_SECTION_HEADER>(hProc, image_section_header + (sizeof(IMAGE_SECTION_HEADER) * i));
			continue;
		}

		section_base = dwModule + section_headers_base.VirtualAddress;
		section_size = section_headers_base.SizeOfRawData;
		break;
	}
	if (!section_base)
		return false;

	//	pass result
	*lpResult = section_base;
	*szImage = section_size;

	return true;
}

bool exMemory::FindPatternEx(const HANDLE& hProc, const std::string& moduleName, const std::string& signature, i64_t* lpResult, int padding, bool isRelative, EASM instruction)
{
	i64_t dwModuleBase = 0;
	if (!GetModuleAddressEx(hProc, moduleName, &dwModuleBase) || !dwModuleBase)
		return false;

	return FindPatternEx(hProc, dwModuleBase, signature, lpResult, padding, isRelative, instruction);
}

bool exMemory::FindPatternEx(const HANDLE& hProc, const i64_t& dwModule, const std::string& signature, i64_t* lpResult, int padding, bool isRelative, EASM instruction)
{
	static auto pattern_to_byte = [](const char* pattern)
		{
			const auto start = const_cast<char*>(pattern);
			const auto end = const_cast<char*>(pattern) + strlen(pattern);

			auto bytes = std::vector<int>{};
			for (auto current = start; current < end; ++current)
			{
				if (*current == '?')
				{
					++current;
					bytes.push_back(-1);
				}
				else
				{
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

	i64_t result = 0;

	//	Get .text segment
	i64_t section_base = 0;
	size_t section_size = 0;
	if (!GetSectionHeaderAddressEx(hProc, dwModule, ESECTIONHEADERS::SECTION_TEXT, &section_base, &section_size))
		return false;

	//	get pattern
	const auto pattern_bytes = pattern_to_byte(signature.c_str());
	const auto cbSize = pattern_bytes.size();
	const auto cbData = pattern_bytes.data();

	//	read section
	std::vector<unsigned __int8> scan_bytes(section_size);
	if (!ReadMemoryEx(hProc, section_base, scan_bytes.data(), scan_bytes.size()))
		return false;

	//	iterate through buffer & compare with pattern
	for (auto i = 0ul; i < section_size - cbSize; ++i)
	{
		bool found = true;
		for (auto j = 0ul; j < cbSize; ++j)
		{
			if (scan_bytes[i + j] != cbData[j] && cbData[j] != -1)
			{
				found = false;
				break;
			}
		}

		if (!found)
			continue;

		//	set result address
		auto address = section_base + i;

		//	apply optional padding
		if (padding != NULL)
			address += padding;

		//	pull offset from instruction
		switch (instruction)
		{
			case EASM::ASM_NULL: { result = address; break; }
			case EASM::ASM_MOV: { const auto offset = ReadEx<int>(hProc, address + 3); return isRelative ? result = address + offset + 7 : result = address; }
			case EASM::ASM_CALL: { const auto offset = ReadEx<int>(hProc, address + 1); return isRelative ? result = address + offset + 5 : result = address; }
			case EASM::ASM_LEA: { const auto offset = ReadEx<int>(hProc, address + 3); return isRelative ? result = address + offset + 7 : result = address; }
			case EASM::ASM_CMP: { const auto offset = ReadEx<int>(hProc, address + 2); return isRelative ? result = address + offset + 6 : result = address; }
		}

		break;
	}

	return result;
}

//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------

bool exMemory::ReadMemoryEx(const HANDLE& hProc, const i64_t& addr, void* lpResult, size_t szRead)
{
	SIZE_T size_read{};
	return ReadProcessMemory(hProc, LPCVOID(addr), lpResult, szRead, &size_read) && szRead == size_read;
}

bool exMemory::WriteMemoryEx(const HANDLE& hProc, const i64_t& addr, LPVOID buffer, DWORD szWrite)
{
	SIZE_T size_write{};
	return WriteProcessMemory(hProc, LPVOID(addr), buffer, szWrite, &size_write) && szWrite == size_write;
}

bool exMemory::ReadStringEx(const HANDLE& hProc, const i64_t& addr, const size_t& szString, std::string* lpResult)
{
	size_t bytes_read{};
	char buf[MAX_PATH]{};
	if (!ReadMemoryEx(hProc, addr, buf, szString))
		return false;

	*lpResult = std::string(buf);

	return true;
}

bool exMemory::ReadPointerChainEx(const HANDLE& hProc, const i64_t& addr, const std::vector<unsigned int>& offsets, i64_t* lpResult)
{
	i64_t result = addr;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		result = ReadEx<i64_t>(hProc, result);
		result += offsets[i];
	}

	*lpResult = result;

	return result > 0;
}

bool exMemory::PatchMemoryEx(const HANDLE& hProc, const i64_t& addr, const void* buffer, const DWORD& szWrite)
{
	//	store original protection & set new protection
	DWORD oldprotect;
	if (!VirtualProtectEx(hProc, LPVOID(addr), szWrite, PAGE_EXECUTE_READWRITE, &oldprotect))
		return false;		

	bool result = WriteProcessMemory(hProc, LPVOID(addr), buffer, szWrite, nullptr);			//	write bytes to address
	VirtualProtectEx(hProc, LPVOID(addr), szWrite, oldprotect, &oldprotect);					//	restore memory protection
	return result;
}


//-------------------------------------------------------------------------------------------------
//
//
//-------------------------------------------------------------------------------------------------

/*https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows*/
BOOL CALLBACK exMemory::GetProcWindowEx(HWND window, LPARAM lParam)
{
	auto data = reinterpret_cast<EnumWindowData*>(lParam);

	DWORD windowPID;
	GetWindowThreadProcessId(window, &windowPID);

	bool isMainWindow = GetWindow(window, GW_OWNER) == (HWND)0 && IsWindowVisible(window);
	if (windowPID != data->procId || !isMainWindow)
		return true;

	data->hwnd = window;

	return true;
}