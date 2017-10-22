#include "libPhysMem.h"

BOOLEAN MapPhysicalMemory(HANDLE hMemory, PDWORD64 pDwAddress, PSIZE_T pSize, PDWORD64 pDwVirtualAddress)
{
	NTSTATUS ntStatus;

	LARGE_INTEGER viewBase;
	*pDwVirtualAddress = 0;
	viewBase.QuadPart = *pDwAddress;
	ntStatus = NtMapViewOfSection(hMemory, GetCurrentProcess(), (void**)pDwVirtualAddress, 0L, *pSize, &viewBase, pSize, ViewShare, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(ntStatus)) 
		return false;
	*pDwAddress = viewBase.QuadPart;
	return true;
}

BOOLEAN UnmapPhysicalMemory(PDWORD64 Address)
{
	if (!NtUnmapViewOfSection(GetCurrentProcess(), (void*)Address))
		return true;
	else
		return false;
}

bool MapAllRam(HANDLE hMemory, void** outBuffer) {
	char* addr = 0;
	auto toRead = 0xFFFFFFFFULL * 2; //Map 8GB of RAM
	return MapPhysicalMemory(hMemory, (PDWORD64)&addr, &toRead, (PDWORD64)outBuffer);
}

bool ReadPhysicalMemory(HANDLE hMemory, LPCVOID lpOffset, LPVOID lpBuffer, SIZE_T size, PSIZE_T read) {
	LPVOID pTmpBuffer;

	if (!MapPhysicalMemory(hMemory, (PDWORD64)&lpOffset, &size, (PDWORD64)&pTmpBuffer)) {
		if (read)
			*read = 0;
		return false;
	}

	if (read)
		*read = size;

	memcpy(lpBuffer, pTmpBuffer, size);
	
	if (!UnmapPhysicalMemory((PDWORD64)pTmpBuffer))
		return false;

	return true;
}


HANDLE GetPhysicalMemoryHandle() {

	UNICODE_STRING		usDeviceName;
	WCHAR				wszDeviceName[] = L"\\device\\physicalmemory";
	HANDLE				hMemory;

	OBJECT_ATTRIBUTES	attributes;
	NTSTATUS			status;

	RtlInitUnicodeString(&usDeviceName, wszDeviceName);
	InitializeObjectAttributes(&attributes, &usDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(NtOpenSection(&hMemory, SECTION_ALL_ACCESS, &attributes)))
		return NULL;
	return hMemory;

}