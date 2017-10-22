#ifndef _SUPERFETCH_H
#define _SUPERFETCH_H
#include <stdint.h>

struct SFMemoryInfo
{
	uint64_t Start;
	uint64_t End;
	int PageCount;
	uint64_t Size;
};

bool SFSetup();
bool SFGetMemoryInfo(SFMemoryInfo* pInfo, int& rCount);


#endif