#pragma once
#include <windows.h>

#include <stdint.h>
typedef struct _POOL_HEADER
{
	union
	{
		struct
		{
#if defined(_AMD64_)
			ULONG	PreviousSize : 8;
			ULONG	PoolIndex : 8;
			ULONG	BlockSize : 8;
			ULONG	PoolType : 8;
#else
			USHORT	PreviousSize : 9;
			USHORT	PoolIndex : 7;
			USHORT	BlockSize : 9;
			USHORT	PoolType : 7;
#endif
		};
		ULONG	Ulong1;
	};
#if defined(_WIN64)
	ULONG	PoolTag;
#endif
	union
	{
#if defined(_WIN64)
		void	*ProcessBilled;
#else
		ULONG	PoolTag;
#endif
		struct
		{
			USHORT	AllocatorBackTraceIndex;
			USHORT	PoolTagHash;
		};
	};
} POOL_HEADER, *PPOOL_HEADER;

typedef struct _OBJECT_HEADER
{
	LONG	PointerCount;
	union
	{
		LONG	HandleCount;
		PVOID	NextToFree;
	};
	uint64_t	Lock;
	UCHAR		TypeIndex;
	union
	{
		UCHAR	TraceFlags;
		struct
		{
			UCHAR	DbgRefTrace : 1;
			UCHAR	DbgTracePermanent : 1;
			UCHAR	Reserved : 6;
		};
	};
	UCHAR	InfoMask;
	union
	{
		UCHAR	Flags;
		struct
		{
			UCHAR	NewObject : 1;
			UCHAR	KernelObject : 1;
			UCHAR	KernelOnlyAccess : 1;
			UCHAR	ExclusiveObject : 1;
			UCHAR	PermanentObject : 1;
			UCHAR	DefaultSecurityQuota : 1;
			UCHAR	SingleHandleEntry : 1;
			UCHAR	DeletedInline : 1;
		};
	};
	union
	{
		PVOID	ObjectCreateInfo;
		PVOID	QuotaBlockCharged;
	};
	PVOID	SecurityDescriptor;
	PVOID	Body;
} OBJECT_HEADER, *POBJECT_HEADER;