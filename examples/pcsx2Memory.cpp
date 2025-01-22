#include <extensions/pcsx2/pcsx2Memory.hpp>
//	#include <fstream>	// enable for file dump

/*
	STRUCTS
	- CZSeal
	- Vec3
	- CZSealPlayer
	- CZSealModel
*/

#pragma region STRUCTS
struct Vec3
{
	float x, y, z;
};

//	SOCOM II r0001
struct CZSealPlayer
{
	unsigned int					pVTable;				//0x0000
	char							pad_0004[16];			//0x0004
	unsigned int					pName;					//0x0014
	char							pad_0018[4];			//0x0018
	Vec3							Position;				//0x001C
	unsigned int					pModel;					//0x0028
	char							pad_002C[156];			//0x002C
	unsigned int					TeamID;					//0x00C8
	char							pad_00CC[1768];			//0x00CC
	unsigned int					PrimaryMags[10];		//0x07B4
	unsigned int					SecondaryMags[3];		//0x07DC
	char							pad_07E8[28];			//0x07E8
	unsigned int					EqSlot1Ammo;			//0x0804
	char							pad_0808[36];			//0x0808
	unsigned int					EqSlot2Ammo;			//0x082C
	char							pad_0830[36];			//0x0830
	unsigned int					EqSlot3Ammo;			//0x0854
	char							pad_0858[2028];			//0x0858
	float							mHealth;				//0x1044
};	//Size: 0x1048

struct CZSealModel
{
	char							pad_0000[32];			//0x0000
	float							Pitch;					//0x0020
	char							pad_0024[4];			//0x0024
	float							Yaw;					//0x0028
	char							pad_002C[4];			//0x002C
	Vec3							Origin;					//0x0030
};	//Size: 0x003C
#pragma endregion

static const unsigned int& oRenderFix = 0x33CD68;	//	DWORD	;	 credit Harry62
static const unsigned int& oLocalCZSeal = 0x440C38;	//	CZSealPlayer*
int main()
{
	pcsx2Memory mem = pcsx2Memory();	//	attach to pcsx2 "pcsx2-qt.exe
	auto pInfo = mem.psxGetInfo();		//	gets pcsx2 process information
	if (!pInfo.bAttached)				//	check if attached
	{
		printf("failed to attach to pcsx2\n");
		return 0;
	}
	
	//	READ PS2 OFFSET
	{
		const auto pLocalSeal = mem.psxRead<unsigned __int32>(oLocalCZSeal);
		if (!pLocalSeal)
		{
			printf("[!] failed to read local seal.\npress any key to exit.");
			getchar();
			return 0;
		}
		const auto iRenderFix = mem.psxRead<unsigned __int32>(oRenderFix);
		if (!iRenderFix)
		{
			printf("[!] failed to read render fix instruction.\npress any key to exit.");
			getchar();
			return 0;
		}
	}

	//	READ POINTERS
	{
		//	version 1
		const auto pLocalSeal = mem.psxRead<unsigned __int32>(oLocalCZSeal);	//	read pointer at offset
		if (!pLocalSeal)
		{
			printf("[!] failed to read local seal\npress any key to exit.");
			getchar();
			return 0;
		}
		CZSealPlayer seal = mem.psxRead<CZSealPlayer>(pLocalSeal);				//	read object at base address
		
		//	version 2
		const auto& seal2 = mem.psxReadPTR<CZSealPlayer>(oLocalCZSeal);			//	pass offset to read object
		auto name = mem.psxReadString(seal.pName);								//	read string* at offset
	}

	//	READ POINTER CHAINS
	{
		//	version 1 chain
		std::vector<unsigned __int32> offsets = { 0x28, 0x30 };					//	declare offsets
		i64_t addr = mem.psxReadPointerChain(oLocalCZSeal, offsets);			//	get address 
		auto vec1 = mem.Read<Vec3>(addr);										//	read at obtained address	-> origin position
		
		//	version 2 chain
		auto vec2 = mem.psxReadChain<Vec3>(oLocalCZSeal, offsets);				//	read from offset chain -> origin position
	}

	//	WRITE POINTER CHAINS
	{
		auto seal = mem.psxReadPTR<CZSealPlayer>(oLocalCZSeal);
		seal.PrimaryMags[0] = 1337;
		mem.psxWritePTR<CZSealPlayer>(oLocalCZSeal, seal);						//	writes object with new data -> 1337 bullets in the first primary mag

		std::vector<unsigned int> offsets3{ offsetof(CZSealPlayer, CZSealPlayer::SecondaryMags[0]) };	//	declare offsets
		mem.psxWriteChain(oLocalCZSeal, offsets3, 1337);						//	write 1337 bullets to the first secondary mag 
	}

	//	PATCH MEMORY
	{
		static std::vector<BYTE> o_bytes(sizeof(DWORD));
		mem.psxReadMemory(oRenderFix, o_bytes.data(), o_bytes.size());			//	read 4 bytes into buffer

		//	apply patch
		static auto p_bytes = std::vector<BYTE>{ 0xDB, 0x00, 0x00, 0x10 };		//	0x100000DB
		mem.psxPatchMemory(oRenderFix, p_bytes.data(), p_bytes.size());			//	patch 4 bytes

		//	restore patch
		mem.psxPatchMemory(oRenderFix, o_bytes.data(), o_bytes.size());			//	patch 4 bytes
	}

	///	DUMP EE SECTION
	//	{
	//		std::vector<BYTE> memdump((1024 * 1024) * 32);	//	32MB ?
	//		mem.psxReadMemory(0x0, memdump.data(), memdump.size());
	//	
	//		//	print out section
	//		//	const auto& eemem = mem.psxGetEEMemory();
	//		//	printf("0x%llX: ", eemem);
	//		//	for (int i = 0; i < 4096; i++)
	//		//	{
	//		//		printf("%02X ", memdump[i]);
	//		//		if ((i + 1) % 4 == 0)
	//		//			printf("\n0x%llX: ", (eemem + i) + 1);
	//		//	}
	//		//	printf("read bytes");
	//		
	//		//	dump section to disk
	//		char exePath[MAX_PATH];
	//		GetModuleFileNameA(0, exePath, MAX_PATH);
	//		std::string path = exePath;
	//		size_t pos = path.find_last_of("\\/");
	//		if (pos != std::string::npos)
	//			path = path.substr(0, pos);
	//	
	//		std::string filePath = path + "\\memdump.bin";
	//		std::ofstream outFile(filePath, std::ios::binary);
	//		if (!outFile)
	//		{
	//			printf("failed to open file\n");
	//			return 0;
	//		}
	//	
	//		outFile.write(reinterpret_cast<const char*>(memdump.data()), memdump.size());
	//		outFile.close();
	//	}
}
