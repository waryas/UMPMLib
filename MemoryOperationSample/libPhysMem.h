#pragma once
#include "ntdll.h"

HANDLE GetPhysicalMemoryHandle();

BOOLEAN MapPhysicalMemory(HANDLE hMemory, PDWORD64 pDwAddress, PSIZE_T pSize, PDWORD64 pDwVirtualAddress);
BOOLEAN UnmapPhysicalMemory(PDWORD64 Address);

bool ReadPhysicalMemory(HANDLE hMemory, LPCVOID lpOffset, LPVOID lpBuffer, SIZE_T size, PSIZE_T read);
bool MapAllRam(HANDLE hMemory, void** outBuffer);