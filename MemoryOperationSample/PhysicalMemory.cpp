#include "PhysicalMemory.h"

typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT, *PSECTION_INHERIT;

extern "C" NTSTATUS NTAPI	ZwOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
extern "C" NTSTATUS NTAPI	ZwMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
	_Inout_ PVOID BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType,
	_In_ ULONG Win32Protect);
extern "C" NTSTATUS NTAPI	ZwUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

BOOLEAN MapPhysicalMemory(HANDLE hMemory, PDWORD64 pDwAddress, PSIZE_T pSize, PDWORD64 pDwVirtualAddress)
{
	NTSTATUS ntStatus;

	LARGE_INTEGER viewBase;
	*pDwVirtualAddress = 0;
	viewBase.QuadPart = *pDwAddress;
	ntStatus = ZwMapViewOfSection(hMemory, GetCurrentProcess(), (void**)pDwVirtualAddress, 0L, *pSize, &viewBase, pSize, ViewShare, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(ntStatus))
		return false;
	*pDwAddress = viewBase.QuadPart;
	return true;
}

BOOLEAN UnmapPhysicalMemory(PDWORD64 Address)
{
	if (!ZwUnmapViewOfSection(GetCurrentProcess(), (void*)Address))
		return true;
	else
		return false;
}


HANDLE OpenPhysicalMemory()
{
	UNICODE_STRING		physmemString;
	OBJECT_ATTRIBUTES	attributes;
	WCHAR				physmemName[] = L"\\device\\physicalmemory";
	NTSTATUS			status;
	HANDLE				physmem;

	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes);

	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	return physmem;
}

int isAscii(int c)
{
	return((c >= 'A' && c <= 'z') || (c >= '0' && c <= '9') || c == 0x20 || c == '@' || c == '_' || c == '?');
}

int isPrintable(uint32_t uint32)
{
	if ((isAscii((uint32 >> 24) & 0xFF)) && (isAscii((uint32 >> 16) & 0xFF)) && (isAscii((uint32 >> 8) & 0xFF)) &&
		(isAscii((uint32) & 0xFF)))
		return true;
	else
		return false;
}
