/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    mspyKern.h

Abstract:
    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    only visible within the kernel.

Environment:

    Kernel mode

--*/
#ifndef __MSPYKERN_H__
#define __MSPYKERN_H__

#include <fltKernel.h>
//#include <dontuse.h>
#include <suppress.h>
#include "minispy.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
//  Memory allocation tag
//

#define SPY_TAG 'ypSM'

//
//  Win8 define for support of NPFS/MSFS
//  Win7 define for support of new ECPs.
//  Vista define for including transaction support,
//  older ECPs
//

#define MINISPY_WIN8     (NTDDI_VERSION >= NTDDI_WIN8)
#define MINISPY_WIN7     (NTDDI_VERSION >= NTDDI_WIN7)
#define MINISPY_VISTA    (NTDDI_VERSION >= NTDDI_VISTA)
#define MINISPY_NOT_W2K  (OSVER(NTDDI_VERSION) > NTDDI_WIN2K)

//
//  Define callback types for Vista
//

#if MINISPY_VISTA

//
//  Dynamically imported Filter Mgr APIs
//

typedef NTSTATUS
(*PFLT_SET_TRANSACTION_CONTEXT)(
    _In_ PFLT_INSTANCE Instance,
    _In_ PKTRANSACTION Transaction,
    _In_ FLT_SET_CONTEXT_OPERATION Operation,
    _In_ PFLT_CONTEXT NewContext,
    _Outptr_opt_ PFLT_CONTEXT *OldContext
    );

typedef NTSTATUS
(*PFLT_GET_TRANSACTION_CONTEXT)(
    _In_ PFLT_INSTANCE Instance,
    _In_ PKTRANSACTION Transaction,
    _Outptr_ PFLT_CONTEXT *Context
    );

typedef NTSTATUS
(*PFLT_ENLIST_IN_TRANSACTION)(
    _In_ PFLT_INSTANCE Instance,
    _In_ PKTRANSACTION Transaction,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ NOTIFICATION_MASK NotificationMask
    );

//
// Flags for the known ECPs
//

#define ECP_TYPE_FLAG_PREFETCH                   0x00000001

#if MINISPY_WIN7

#define ECP_TYPE_FLAG_OPLOCK_KEY                 0x00000002
#define ECP_TYPE_FLAG_NFS                        0x00000004
#define ECP_TYPE_FLAG_SRV                        0x00000008

#endif

#define ADDRESS_STRING_BUFFER_SIZE          64

//
//  Enumerate the ECPs MiniSpy supports
//

typedef enum _ECP_TYPE {

    EcpPrefetchOpen,
    EcpOplockKey,
    EcpNfsOpen,
    EcpSrvOpen,

    NumKnownEcps

} ECP_TYPE;

#endif

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------
#define RESET_INTERVAL_TICKS       10000000 // 1 detik (dalam satuan 100ns)
#define MAX_FILE_OPENS_PER_SECOND  50   // Jika > 20 file/detik = Ransomware
#define MAX_FILE_RENAMES_PER_SECOND 5
#define MAX_UNIQUE_DIRS 5             // Batas Folder Unik
#define MAX_DIR_LENGTH 260
typedef enum _OP_TYPE {
    OP_TYPE_OPEN,
    OP_TYPE_RENAME
} OP_TYPE;
typedef struct _PROCESS_STATS {
    ULONG ProcessId;            // Siapa prosesnya
    ULONG FileOpenCount;    // Counter untuk Create/Open
    ULONG FileRenameCount;  // Counter untuk Rename (BARU)
    LARGE_INTEGER LastResetTime; // Kapan terakhir counter di-reset
    BOOLEAN IsWhitelisted;
    INT IsSigned;
    UNICODE_STRING ImagePath;
    LIST_ENTRY ListEntry;       // Untuk menyambung ke linked list
} PROCESS_STATS, * PPROCESS_STATS;
// =============================================================
// DEFINISI NATIVE API UNTUK SNAPSHOT PROCESS
// =============================================================

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId; // <--- KITA BUTUH INI
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);
typedef struct _WHITELIST_ENTRY {
    UNICODE_STRING ImagePath;
    LIST_ENTRY ListEntry;
} WHITELIST_ENTRY, * PWHITELIST_ENTRY;

// Global Variable untuk Whitelist Path
LIST_ENTRY g_WhitelistHead;
KGUARDED_MUTEX g_WhitelistLock;


// Global List Head & Lock
LIST_ENTRY g_ProcessStatsList;
KGUARDED_MUTEX g_StatsLock;

// Log2 table: 1024 * log2(i / 256)
// Kita menggunakan nilai absolut agar perhitungan lebih mudah
static const USHORT Log2Table[257] = {
    0, 8192, 7168, 6569, 6144, 5814, 5545, 5318, 5120, 4944, 4786, 4643, 4513, 4393, 4282, 4179,
    4083, 3993, 3908, 3828, 3753, 3681, 3613, 3548, 3486, 3427, 3370, 3315, 3263, 3212, 3163, 3116,
    3070, 3026, 2983, 2942, 2901, 2862, 2823, 2786, 2750, 2714, 2679, 2646, 2612, 2580, 2548, 2517,
    2486, 2456, 2427, 2398, 2369, 2342, 2314, 2287, 2261, 2235, 2209, 2184, 2159, 2135, 2111, 2087,
    2064, 2041, 2018, 1996, 1974, 1952, 1931, 1910, 1889, 1869, 1848, 1828, 1809, 1789, 1770, 1751,
    1732, 1714, 1695, 1677, 1659, 1642, 1624, 1607, 1590, 1573, 1556, 1540, 1523, 1507, 1491, 1475,
    1459, 1444, 1428, 1413, 1398, 1383, 1368, 1353, 1339, 1324, 1310, 1296, 1282, 1268, 1254, 1241,
    1227, 1214, 1200, 1187, 1174, 1161, 1148, 1135, 1122, 1110, 1097, 1085, 1073, 1060, 1048, 1036,
    1024, 1012, 1000, 989, 977, 966, 954, 943, 932, 921, 910, 899, 888, 877, 866, 856,
    845, 835, 824, 814, 804, 794, 784, 774, 764, 754, 744, 735, 725, 715, 706, 696,
    687, 678, 668, 659, 650, 641, 632, 623, 614, 605, 596, 587, 579, 570, 562, 553,
    545, 536, 528, 520, 511, 503, 495, 487, 479, 471, 463, 455, 447, 440, 432, 424,
    417, 409, 402, 394, 387, 379, 372, 365, 357, 350, 343, 336, 329, 321, 314, 307,
    300, 293, 286, 280, 273, 266, 259, 253, 246, 239, 233, 226, 220, 213, 207, 201,
    194, 188, 182, 175, 169, 163, 157, 151, 145, 139, 133, 127, 121, 115, 109, 103,
    97, 91, 85, 80, 74, 68, 62, 57, 51, 46, 40, 35, 29, 24, 18, 13
};

typedef struct _MINISPY_DATA {

    //
    //  The object that identifies this driver.
    //

    PDRIVER_OBJECT DriverObject;

    //
    //  The filter that results from a call to
    //  FltRegisterFilter.
    //

    PFLT_FILTER Filter;

    //
    //  Server port: user mode connects to this port
    //

    PFLT_PORT ServerPort;

    //
    //  Client connection port: only one connection is allowed at a time.,
    //

    PFLT_PORT ClientPort;

    //
    //  List of buffers with data to send to user mode.
    //

    KSPIN_LOCK OutputBufferLock;
    LIST_ENTRY OutputBufferList;

    //
    //  Lookaside list used for allocating buffers.
    //

    NPAGED_LOOKASIDE_LIST FreeBufferList;

    //
    //  Variables used to throttle how many records buffer we can use
    //

    LONG MaxRecordsToAllocate;
    __volatile LONG RecordsAllocated;

    //
    //  static buffer used for sending an "out-of-memory" message
    //  to user mode.
    //

    __volatile LONG StaticBufferInUse;

    //
    //  We need to make sure this buffer aligns on a PVOID boundary because
    //  minispy casts this buffer to a RECORD_LIST structure.
    //  That can cause alignment faults unless the structure starts on the
    //  proper PVOID boundary
    //

    PVOID OutOfMemoryBuffer[RECORD_SIZE/sizeof( PVOID )];

    //
    //  Variable and lock for maintaining LogRecord sequence numbers.
    //

    __volatile LONG LogSequenceNumber;

    //
    //  The name query method to use.  By default, it is set to
    //  FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, but it can be overridden
    //  by a setting in the registery.
    //

    ULONG NameQueryMethod;

    //
    //  Global debug flags
    //

    ULONG DebugFlags;

#if MINISPY_VISTA

    //
    //  Dynamically imported Filter Mgr APIs
    //

    PFLT_SET_TRANSACTION_CONTEXT PFltSetTransactionContext;

    PFLT_GET_TRANSACTION_CONTEXT PFltGetTransactionContext;

    PFLT_ENLIST_IN_TRANSACTION PFltEnlistInTransaction;

#endif

} MINISPY_DATA, *PMINISPY_DATA;


//
//  Defines the minispy context structure
//

typedef struct _MINISPY_TRANSACTION_CONTEXT {
    ULONG Flags;
    ULONG Count;

}MINISPY_TRANSACTION_CONTEXT, *PMINISPY_TRANSACTION_CONTEXT;


typedef struct _TARGET_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING FileName;
} TARGET_ENTRY, * PTARGET_ENTRY;

// 2. Deklarasi EXTERN (Memberi tahu file lain bahwa variabel ini ADA di tempat lain)
extern LIST_ENTRY g_TargetListHead;
extern FAST_MUTEX g_TargetListLock;

// =============================================================
// == TAMBAHAN BARU: STRUKTUR WORKER THREAD ==
// =============================================================

typedef struct _CORE_SENTINEL_WORK_ITEM {

    // Header Wajib untuk FltQueueGenericWorkItem
    PFLT_GENERIC_WORKITEM WorkItem;

    // Data yang ingin kita kirimkan
    HANDLE ProcessId;

} CORE_SENTINEL_WORK_ITEM, * PCORE_SENTINEL_WORK_ITEM;
//
//  This macro below is used to set the flags field in minispy's
//  MINISPY_TRANSACTION_CONTEXT structure once it has been
//  successfully enlisted in the transaction.
//

#define MINISPY_ENLISTED_IN_TRANSACTION 0x01

//
//  Minispy's global variables
//

extern MINISPY_DATA MiniSpyData;

#define DEFAULT_MAX_RECORDS_TO_ALLOCATE     500
#define MAX_RECORDS_TO_ALLOCATE             L"MaxRecords"

#define DEFAULT_NAME_QUERY_METHOD           FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP
#define NAME_QUERY_METHOD                   L"NameQueryMethod"

//
//  DebugFlag values
//

#define SPY_DEBUG_PARSE_NAMES   0x00000001

//---------------------------------------------------------------------------
//  Registration structure
//---------------------------------------------------------------------------

extern const FLT_REGISTRATION FilterRegistration;

//---------------------------------------------------------------------------
//  Function prototypes
//---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS
SpyPreOperationCallback (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
SpyKtmNotificationCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG TransactionNotification
    );

NTSTATUS
SpyFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
SpyQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

VOID
SpyReadDriverParameters (
    _In_ PUNICODE_STRING RegistryPath
    );

LONG
SpyExceptionFilter (
    _In_ PEXCEPTION_POINTERS ExceptionPointer,
    _In_ BOOLEAN AccessingUserBuffer
    );

//---------------------------------------------------------------------------
//  Memory allocation routines
//---------------------------------------------------------------------------

PRECORD_LIST
SpyAllocateBuffer (
    _Out_ PULONG RecordType
    );

VOID
SpyFreeBuffer (
    _In_ PVOID Buffer
    );

//---------------------------------------------------------------------------
//  Logging routines
//---------------------------------------------------------------------------
PRECORD_LIST
SpyNewRecord (
    VOID
    );

VOID
SpyFreeRecord (
    _In_ PRECORD_LIST Record
    );

#if MINISPY_VISTA

VOID
SpyParseEcps (
    _In_ PFLT_CALLBACK_DATA Data,
    _Inout_ PRECORD_LIST RecordList,
    _Inout_ PUNICODE_STRING EcpData
    );

VOID
SpyBuildEcpDataString (
    _In_ PRECORD_LIST RecordList,
    _Inout_ PUNICODE_STRING EcpData,
    _In_reads_(NumKnownEcps) PVOID * ContextPointers
    );

VOID
SpySetRecordNameAndEcpData (
    _Inout_ PLOG_RECORD LogRecord,
    _In_ PUNICODE_STRING Name,
    _In_opt_ PUNICODE_STRING EcpData
    );

#else

VOID
SpySetRecordName (
    _Inout_ PLOG_RECORD LogRecord,
    _In_ PUNICODE_STRING Name
    );

#endif

VOID
SpyLogPreOperationData (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PRECORD_LIST RecordList
    );

VOID
SpyLogPostOperationData (
    _In_ PFLT_CALLBACK_DATA Data,
    _Inout_ PRECORD_LIST RecordList
    );

VOID
SpyLogTransactionNotify (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PRECORD_LIST RecordList,
    _In_ ULONG TransactionNotification
    );

VOID
SpyLog (
    _In_ PRECORD_LIST RecordList
    );

NTSTATUS
SpyGetLog (
    _Out_writes_bytes_to_(OutputBufferLength,*ReturnOutputBufferLength) PUCHAR OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

VOID
SpyEmptyOutputBufferList (
    VOID
    );

VOID
SpyDeleteTxfContext (
    _Inout_ PFLT_CONTEXT  Context,
    _In_ FLT_CONTEXT_TYPE  ContextType
    );
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);
#endif  //__MSPYKERN_H__

