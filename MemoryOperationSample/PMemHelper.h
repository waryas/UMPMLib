#ifndef _PMEM_HELPER_H
#define _PMEM_HELPER_H
#include <Windows.h>
#include <stdint.h>
#include <vector>
#include <functional>
#include "Superfetch.h"
#include "PhysicalMemory.h"

class PMemHelper
{
public:
	PMemHelper()
	{

		// get system version

		// win7
		//EPNameOffset = 0x2E0;
		//EPPidOffset = 0xcc;
		//EPDirBaseOffset = 0x0028;
		//EPBaseOffset = 0x270;
		//EPLinkOffset = 0xcc;

		// win10 1703
		EPNameOffset = 0x450;
		EPPidOffset = 0x02E0;
		EPDirBaseOffset = 0x0028;
		EPBaseOffset = 0x03C0;
		EPLinkOffset = 0x02E8;
		
		SFSetup();	
		SFGetMemoryInfo(mMemInfo, mInfoCount);

		mPMemHandle = OpenPhysicalMemory();

		for (int i = 0; i < mInfoCount; i++)
		{
			uint64_t pointer = 0;
			mMemInfo[i].Start -= 0x1000;
			mMemInfo[i].End -= 0x1000;
			if (MapPhysicalMemory(mPMemHandle, &mMemInfo[i].Start, &mMemInfo[i].Size, &pointer))
				mpPointers.push_back(pointer);
			else
				printf("failed to map %d to %d \n", mMemInfo[i].Start, mMemInfo[i].End);
		}		
	}

	~PMemHelper()
	{
		for(auto pointer: mpPointers)
			UnmapPhysicalMemory((PDWORD64)pointer);
	}

	bool Read(uint64_t address, uint8_t* buffer, int size)
	{
		for (int i = 0; i < mInfoCount; i++)
		{
			if (mMemInfo[i].Start <= address && address + size <= mMemInfo[i].End)
			{
				memcpy(buffer, (void*)(mpPointers[i] + address - mMemInfo[i].Start), size);
				return true;
			}
		}
		return false;
	}

	bool Write(uint64_t address, uint8_t* buffer, int size)
	{
		for (int i = 0; i < mInfoCount; i++)
		{
			if (mMemInfo[i].Start <= address && address + size <= mMemInfo[i].End)
			{
				memcpy((void*)(mpPointers[i] + address - mMemInfo[i].Start), buffer, size);
				return true;
			}
		}
		return false;
	}

	bool ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size)
	{
		auto paddress = TranslateLinearAddress(dirbase, address);
		return Read(paddress, buffer, size);
	}

	bool WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size)
	{
		auto paddress = TranslateLinearAddress(dirbase, address);
		return Write(paddress, buffer, size);
	}

	uint64_t GetProcessBase(int pid)
	{
		uint64_t base = 0;
		ReadVirtual(GetKernelDirBase(), GetEProcess(pid) + EPBaseOffset, (uint8_t*)&base, sizeof(base));
		return base;
	}

	uint64_t GetDirBase(int pid)
	{
		uint64_t cr3 = 0;
		if (ReadVirtual(GetKernelDirBase(), GetEProcess(pid) + EPDirBaseOffset, (uint8_t*)&cr3, sizeof(cr3)))
			return cr3;
		return 0;
	}

	uint64_t GetKernelDirBase()
	{
		if (mKernelDir != 0)
			return mKernelDir;
		
		auto result = ScanPoolTag("Proc", [&](uint64_t address) -> bool
		{ 
			uint64_t peprocess;
			char buffer[0xFFFF];
			if (!Read(address, (uint8_t*)buffer, sizeof(buffer)))
				return false;
			for (char* ptr = buffer; (uint64_t)ptr - (uint64_t)buffer <= sizeof(buffer); ptr++)
				if (!strcmp(ptr, "System"))
					peprocess = address + (uint64_t)ptr - (uint64_t)buffer - EPNameOffset;

			uint64_t pid = 0;
			if (!Read(peprocess + EPPidOffset, (uint8_t*)&pid, sizeof(pid)))
				return false;

			if (pid == 4)
			{
				if (!Read(peprocess + EPDirBaseOffset, (uint8_t*)&mKernelDir, sizeof(mKernelDir)))
					return false;
				printf("Kernel cr3: %d \n", mKernelDir);
				if (peprocess == TranslateLinearAddress(mKernelDir, SFGetEProcess(4)))
					return true;		
			}
			return false;
		});

		if (result)
			return mKernelDir;
		return 0;
	}

private:
	uint64_t EPNameOffset    = 0;
	uint64_t EPPidOffset     = 0;
	uint64_t EPDirBaseOffset = 0;
	uint64_t EPBaseOffset    = 0;
	uint64_t EPLinkOffset    = 0;

private:
	HANDLE mPMemHandle;
	SFMemoryInfo mMemInfo[255];
	int mInfoCount = 0;
	std::vector<uint64_t> mpPointers;
	uint64_t mKernelDir = 0;

	bool ScanPoolTag(char* tag_char, std::function<bool(uint64_t)> scan_callback)
	{
		uint32_t tag = (
			tag_char[0] |
			tag_char[1] << 8   |
			tag_char[2] << 16  |
			tag_char[3] << 24
			);

		uint8_t lpBuffer[0x1000] = { 0 };
		for (auto i = 0ULL; i< mMemInfo[mInfoCount-1].End; i += 0x1000) {
			if (!Read(i, lpBuffer, 0x1000))
				continue;
			uint8_t* lpCursor = lpBuffer;
			uint32_t previousSize = 0;
			while (true) {	
				auto pPoolHeader = (PPOOL_HEADER)lpCursor;
				auto blockSize = (pPoolHeader->BlockSize << 4);
				auto previousBlockSize = (pPoolHeader->PreviousSize << 4);
		
				if (previousBlockSize != previousSize || 
					blockSize == 0 || 
					blockSize >= 0xFFF || 
					!isPrintable(pPoolHeader->PoolTag & 0x7FFFFFFF))
					break;
		
				previousSize = blockSize;
		
				if (tag == pPoolHeader->PoolTag)
					if (scan_callback(i + (uint64_t)lpCursor - (uint64_t)lpBuffer))
						return true;
				lpCursor += blockSize;
				if ((lpCursor - lpBuffer) >= 0x1000)
					break;
		
			}
		}

		return false;
	}

	uint64_t GetEProcess(int pid)
	{	
		_LIST_ENTRY ActiveProcessLinks;
		ReadVirtual(GetKernelDirBase(), SFGetEProcess(4) + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks));

		while (true)
		{
			uint64_t next_pid = 0;
			uint64_t next_link = (uint64_t)(ActiveProcessLinks.Flink);
			uint64_t next = next_link - EPLinkOffset;
			ReadVirtual(GetKernelDirBase(), next + EPPidOffset, (uint8_t*)&next_pid, sizeof(next_pid));
			ReadVirtual(GetKernelDirBase(), next + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks));
			if (next_pid == pid)
				return next;
			if (next_pid == 4)
				return 0;
		}		

		return 0;
	}

	uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress)
	{
		uint16_t PML4 = (uint16_t)((virtualAddress >> 39) & 0x1FF);         //<! PML4 Entry Index
		uint16_t DirectoryPtr = (uint16_t)((virtualAddress >> 30) & 0x1FF); //<! Page-Directory-Pointer Table Index
		uint16_t Directory = (uint16_t)((virtualAddress >> 21) & 0x1FF);    //<! Page Directory Table Index
		uint16_t Table = (uint16_t)((virtualAddress >> 12) & 0x1FF);        //<! Page Table Index

																		// Read the PML4 Entry. DirectoryTableBase has the base address of the table.
																		// It can be read from the CR3 register or from the kernel process object.
		uint64_t PML4E = 0;// ReadPhysicalAddress<ulong>(directoryTableBase + (ulong)PML4 * sizeof(ulong));
		Read(directoryTableBase + (uint64_t)PML4 * sizeof(uint64_t), (uint8_t*)&PML4E, sizeof(PML4E));

		if (PML4E == 0)
			return 0;

		// The PML4E that we read is the base address of the next table on the chain,
		// the Page-Directory-Pointer Table.
		uint64_t PDPTE = 0;// ReadPhysicalAddress<ulong>((PML4E & 0xFFFF1FFFFFF000) + (ulong)DirectoryPtr * sizeof(ulong));
		Read((PML4E & 0xFFFF1FFFFFF000) + (uint64_t)DirectoryPtr * sizeof(uint64_t), (uint8_t*)&PDPTE, sizeof(PDPTE));

		if (PDPTE == 0)
			return 0;

		//Check the PS bit
		if ((PDPTE & (1 << 7)) != 0)
		{
			// If the PDPTE¨s PS flag is 1, the PDPTE maps a 1-GByte page. The
			// final physical address is computed as follows:
			// ！ Bits 51:30 are from the PDPTE.
			// ！ Bits 29:0 are from the original va address.
			return (PDPTE & 0xFFFFFC0000000) + (virtualAddress & 0x3FFFFFFF);
		}

		// PS bit was 0. That means that the PDPTE references the next table
		// on the chain, the Page Directory Table. Read it.
		uint64_t PDE = 0;// ReadPhysicalAddress<ulong>((PDPTE & 0xFFFFFFFFFF000) + (ulong)Directory * sizeof(ulong));
		Read((PDPTE & 0xFFFFFFFFFF000) + (uint64_t)Directory * sizeof(uint64_t), (uint8_t*)&PDE, sizeof(PDE));

		if (PDE == 0)
			return 0;

		if ((PDE & (1 << 7)) != 0)
		{
			// If the PDE¨s PS flag is 1, the PDE maps a 2-MByte page. The
			// final physical address is computed as follows:
			// ！ Bits 51:21 are from the PDE.
			// ！ Bits 20:0 are from the original va address.
			return (PDE & 0xFFFFFFFE00000) + (virtualAddress & 0x1FFFFF);
		}

		// PS bit was 0. That means that the PDE references a Page Table.
		uint64_t PTE = 0;// ReadPhysicalAddress<ulong>((PDE & 0xFFFFFFFFFF000) + (ulong)Table * sizeof(ulong));
		Read((PDE & 0xFFFFFFFFFF000) + (uint64_t)Table * sizeof(uint64_t), (uint8_t*)&PTE, sizeof(PTE));

		if (PTE == 0)
			return 0;

		// The PTE maps a 4-KByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:12 are from the PTE.
		// ！ Bits 11:0 are from the original va address.
		return (PTE & 0xFFFFFFFFFF000) + (virtualAddress & 0xFFF);
	}
};


#endif
