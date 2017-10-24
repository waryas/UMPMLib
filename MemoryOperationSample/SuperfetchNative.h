#ifndef _SUPERFETCH_NATIVE_H
#define _SUPERFETCH_NATIVE_H
#pragma comment(lib, "ntdll.lib")
#define _AMD64_
#include <minwindef.h>

typedef long NTSTATUS, *PNTSTATUS;
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#include <ntstatus.h>



typedef enum _SUPERFETCH_INFORMATION_CLASS {
	SuperfetchRetrieveTrace = 1,        // Query
	SuperfetchSystemParameters = 2,     // Query
	SuperfetchLogEvent = 3,             // Set
	SuperfetchGenerateTrace = 4,        // Set
	SuperfetchPrefetch = 5,             // Set
	SuperfetchPfnQuery = 6,             // Query
	SuperfetchPfnSetPriority = 7,       // Set
	SuperfetchPrivSourceQuery = 8,      // Query
	SuperfetchSequenceNumberQuery = 9,  // Query
	SuperfetchScenarioPhase = 10,       // Set
	SuperfetchWorkerPriority = 11,      // Set
	SuperfetchScenarioQuery = 12,       // Query
	SuperfetchScenarioPrefetch = 13,    // Set
	SuperfetchRobustnessControl = 14,   // Set
	SuperfetchTimeControl = 15,         // Set
	SuperfetchMemoryListQuery = 16,     // Query
	SuperfetchMemoryRangesQuery = 17,   // Query
	SuperfetchTracingControl = 18,       // Set
	SuperfetchTrimWhileAgingControl = 19,
	SuperfetchInformationMax = 20
} SUPERFETCH_INFORMATION_CLASS;

//
// Buffer for NtQuery/SetInformationSystem for the Superfetch Class
//
typedef struct _SUPERFETCH_INFORMATION {
	ULONG Version;
	ULONG Magic;
	SUPERFETCH_INFORMATION_CLASS InfoClass;
	PVOID Data;
	ULONG Length;
} SUPERFETCH_INFORMATION, *PSUPERFETCH_INFORMATION;

typedef struct _RTL_BITMAP {
	ULONG SizeOfBitMap;
	PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;




typedef struct _PF_PHYSICAL_MEMORY_RANGE {
	ULONG_PTR BasePfn;
	ULONG_PTR PageCount;
} PF_PHYSICAL_MEMORY_RANGE, *PPF_PHYSICAL_MEMORY_RANGE;

typedef struct _PF_MEMORY_RANGE_INFO {
	ULONG Version;
	ULONG RangeCount;
	PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
} PF_MEMORY_RANGE_INFO, *PPF_MEMORY_RANGE_INFO;

typedef struct _PHYSICAL_MEMORY_RUN {
	SIZE_T BasePage;
	SIZE_T PageCount;
} PHYSICAL_MEMORY_RUN, *PPHYSICAL_MEMORY_RUN;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation, /// Obsolete: Use KUSER_SHARED_DATA
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,  // used to be SystemLoadAndCallImage
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformationNative,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation,
	SystemLoadGdiDriverInSystemSpaceInformation,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHanfleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchDogTimerHandler,
	SystemWatchDogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWo64SharedInformationObosolete,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	SystemThreadPriorityClientIdInformation,
	SystemProcessorIdleCycleTimeInformation,
	SystemVerifierCancellationInformation,
	SystemProcessorPowerInformationEx,
	SystemRefTraceInformation,
	SystemSpecialPoolInformation,
	SystemProcessIdInformation,
	SystemErrorPortInformation,
	SystemBootEnvironmentInformation,
	SystemHypervisorInformation,
	SystemVerifierInformationEx,
	SystemTimeZoneInformation,
	SystemImageFileExecutionOptionsInformation,
	SystemCoverageInformation,
	SystemPrefetchPathInformation,
	SystemVerifierFaultsInformation,
	MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

struct RTL_PROCESS_MODULE_INFORMATION
{
	unsigned int Section;
	void* MappedBase;
	void* ImageBase;
	unsigned int ImageSize;
	unsigned int Flags;
	unsigned short LoadOrderIndex;
	unsigned short InitOrderIndex;
	unsigned short LoadCount;
	unsigned short OffsetToFileName;
	char FullPathName[256];
};

struct RTL_PROCESS_MODULES
{
	unsigned int NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[0];
};

struct SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[0];
};

extern "C" NTSTATUS WINAPI NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);


#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << 12)

#define SE_DEBUG_PRIVILEGE                (20L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  (13L)

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(
	IN ULONG Privilege,
	IN BOOLEAN NewValue,
	IN BOOLEAN ForThread,
	OUT PBOOLEAN OldValue
);

#define SPAGE_SIZE              0x1000
#define SUPERFETCH_VERSION      45
#define SUPERFETCH_MAGIC        'kuhC'

#endif