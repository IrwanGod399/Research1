/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    MiniSpy.c

Abstract:

    This is the main module for the MiniSpy mini-filter.

Environment:

    Kernel mode

--*/
#include "mspyKern.h"
#include <stdio.h>
#include <ntstrsafe.h>
#include <ntifs.h>
//  Global variables
//


MINISPY_DATA MiniSpyData;
NTSTATUS StatusToBreakOn = 0;

LIST_ENTRY g_TargetListHead;
FAST_MUTEX g_TargetListLock;
//---------------------------------------------------------------------------
//  Function prototypes
//---------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );


NTSTATUS
SpyMessage (
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
SpyConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
    );

VOID
SpyDisconnect(
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
SpyEnlistInTransaction (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

VOID
CoreSentinelWorkItemRoutine(
    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
    _In_ PVOID FltObjects, // Tidak kita gunakan
    _In_ PVOID Context     // Ini adalah pointer ke struct kita
);


NTSYSAPI
PWCH
NTAPI
RtlFindUnicodeSubstring(
    _In_ PCUNICODE_STRING FullString,
    _In_ PCUNICODE_STRING SearchString,
    _In_ BOOLEAN CaseInSensitive
);
//---------------------------------------------------------------------------
//  Assign text sections for each routine.
//---------------------------------------------------------------------------

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, SpyFilterUnload)
    #pragma alloc_text(PAGE, SpyQueryTeardown)
    #pragma alloc_text(PAGE, SpyConnect)
    #pragma alloc_text(PAGE, SpyDisconnect)
    #pragma alloc_text(PAGE, SpyMessage)
#endif


#define SetFlagInterlocked(_ptrFlags,_flagToSet) \
    ((VOID)InterlockedOr(((volatile LONG *)(_ptrFlags)),_flagToSet))
    
//---------------------------------------------------------------------------
//                      ROUTINES
//---------------------------------------------------------------------------
BOOLEAN AddPathToWhitelist(PUNICODE_STRING Path) {
    PWHITELIST_ENTRY pEntry = NULL;
    PLIST_ENTRY entry;
    BOOLEAN isDuplicate = FALSE;
    if (!Path || !Path->Buffer || Path->Length == 0 || Path->Buffer[0] != L'\\') return FALSE;

    KeAcquireGuardedMutex(&g_WhitelistLock);


    for (entry = g_WhitelistHead.Flink; entry != &g_WhitelistHead; entry = entry->Flink) {
        pEntry = CONTAINING_RECORD(entry, WHITELIST_ENTRY, ListEntry);


        if (RtlEqualUnicodeString(Path, &pEntry->ImagePath, TRUE)) {
            isDuplicate = TRUE;
            break; 
        }
    }

    if (isDuplicate) {
        KeReleaseGuardedMutex(&g_WhitelistLock);
         DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CoreSentinel: [SKIP] Duplicate Path: %wZ\n", Path);
        return FALSE;
    }

    pEntry = (PWHITELIST_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(WHITELIST_ENTRY), 'wlst');
    if (!pEntry) return FALSE;

    RtlZeroMemory(pEntry, sizeof(WHITELIST_ENTRY));

    pEntry->ImagePath.Length = Path->Length;
    pEntry->ImagePath.MaximumLength = Path->Length + sizeof(WCHAR);
    pEntry->ImagePath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, pEntry->ImagePath.MaximumLength, 'str');

    if (!pEntry->ImagePath.Buffer) {
        ExFreePoolWithTag(pEntry, 'wlst');
        return FALSE;
    }

    RtlCopyMemory(pEntry->ImagePath.Buffer, Path->Buffer, Path->Length);
    pEntry->ImagePath.Buffer[Path->Length / sizeof(WCHAR)] = L'\0'; // Null Terminate

    InsertHeadList(&g_WhitelistHead, &pEntry->ListEntry);
    KeReleaseGuardedMutex(&g_WhitelistLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CoreSentinel: [WHITELIST ADD] %wZ\n", &pEntry->ImagePath);
    return TRUE;
}
//=============================================================================
//==========================================================================
VOID WhitelistExistingProcesses() {
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    PSYSTEM_PROCESS_INFORMATION pInfo = NULL;
    LARGE_INTEGER currentTime;
    ULONG count = 0;
    PEPROCESS eProcess = NULL;
    PUNICODE_STRING pPathName = NULL;
    KeQuerySystemTime(&currentTime);

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status)) return;
    bufferSize = returnLength + 4096;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'snap');

    if (!buffer) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CoreSentinel: Gagal Alokasi Memori!\n");
        return;
    }
    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);
    
    if (NT_SUCCESS(status)) {
        pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
        

        KeAcquireGuardedMutex(&g_StatsLock);

        while (TRUE) {
            HANDLE pid = pInfo->UniqueProcessId;
            if ((ULONG)(ULONG_PTR)pid > 4) {
                if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &eProcess))) {

                    if (NT_SUCCESS(SeLocateProcessImageName(eProcess, &pPathName)) && pPathName != NULL) {
                        if (AddPathToWhitelist(pPathName)) {
                            count++;
                        }
                        ExFreePool(pPathName);
                    }

                    ObDereferenceObject(eProcess);
                }
            }
            if (pInfo->NextEntryOffset == 0) break;
            pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
        }

        KeReleaseGuardedMutex(&g_StatsLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "CoreSentinel: [INIT] Total Whitelisted Processes: %d\n", count);
    }

    ExFreePool(buffer);
}


NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This routine is called when a driver first loads.  Its purpose is to
    initialize global state and then register with FltMgr to start filtering.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.
    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Status of the operation.

--*/
{
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    NTSTATUS status = STATUS_SUCCESS;

    try {


        MiniSpyData.LogSequenceNumber = 0;
        MiniSpyData.MaxRecordsToAllocate = DEFAULT_MAX_RECORDS_TO_ALLOCATE;
        MiniSpyData.RecordsAllocated = 0;
        MiniSpyData.NameQueryMethod = DEFAULT_NAME_QUERY_METHOD;

        MiniSpyData.DriverObject = DriverObject;

        InitializeListHead( &MiniSpyData.OutputBufferList );
        KeInitializeSpinLock( &MiniSpyData.OutputBufferLock );
        InitializeListHead(&g_TargetListHead);
        ExInitializeFastMutex(&g_TargetListLock);
        InitializeListHead(&g_ProcessStatsList);
        KeInitializeGuardedMutex(&g_StatsLock);
        InitializeListHead(&g_WhitelistHead);
        KeInitializeGuardedMutex(&g_WhitelistLock);
        WhitelistExistingProcesses();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CoreSentinel: Baseline Whitelist Created.\n");
        ExInitializeNPagedLookasideList( &MiniSpyData.FreeBufferList,
                                         NULL,
                                         NULL,
                                         POOL_NX_ALLOCATION,
                                         RECORD_SIZE,
                                         SPY_TAG,
                                         0 );

#if MINISPY_VISTA

        //
        //  Dynamically import FilterMgr APIs for transaction support
        //

#pragma warning(push)
#pragma warning(disable:4055) // type cast from data pointer to function pointer
        MiniSpyData.PFltSetTransactionContext = (PFLT_SET_TRANSACTION_CONTEXT) FltGetRoutineAddress( "FltSetTransactionContext" );
        MiniSpyData.PFltGetTransactionContext = (PFLT_GET_TRANSACTION_CONTEXT) FltGetRoutineAddress( "FltGetTransactionContext" );
        MiniSpyData.PFltEnlistInTransaction = (PFLT_ENLIST_IN_TRANSACTION) FltGetRoutineAddress( "FltEnlistInTransaction" );
#pragma warning(pop)

#endif

        //
        // Read the custom parameters for MiniSpy from the registry
        //

        SpyReadDriverParameters(RegistryPath);

        //
        //  Now that our global configuration is complete, register with FltMgr.
        //

        status = FltRegisterFilter( DriverObject,
                                    &FilterRegistration,
                                    &MiniSpyData.Filter );

        if (!NT_SUCCESS( status )) {

           leave;
        }


        status  = FltBuildDefaultSecurityDescriptor( &sd,
                                                     FLT_PORT_ALL_ACCESS );

        if (!NT_SUCCESS( status )) {
            leave;
        }

        RtlInitUnicodeString( &uniString, MINISPY_PORT_NAME );

        InitializeObjectAttributes( &oa,
                                    &uniString,
                                    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                    NULL,
                                    sd );

        status = FltCreateCommunicationPort( MiniSpyData.Filter,
                                             &MiniSpyData.ServerPort,
                                             &oa,
                                             NULL,
                                             SpyConnect,
                                             SpyDisconnect,
                                             SpyMessage,
                                             1 );

        FltFreeSecurityDescriptor( sd );

        if (!NT_SUCCESS( status )) {
            leave;
        }

        //
        //  We are now ready to start filtering
        //

        status = FltStartFiltering( MiniSpyData.Filter );

    } finally {

        if (!NT_SUCCESS( status ) ) {

             if (NULL != MiniSpyData.ServerPort) {
                 FltCloseCommunicationPort( MiniSpyData.ServerPort );
             }

             if (NULL != MiniSpyData.Filter) {
                 FltUnregisterFilter( MiniSpyData.Filter );
             }

             ExDeleteNPagedLookasideList( &MiniSpyData.FreeBufferList );
        }
    }

    return status;
}

NTSTATUS
SpyConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
    )
/*++

Routine Description

    This is called when user-mode connects to the server
    port - to establish a connection

Arguments

    ClientPort - This is the pointer to the client port that
        will be used to send messages from the filter.
    ServerPortCookie - unused
    ConnectionContext - unused
    SizeofContext   - unused
    ConnectionCookie - unused

Return Value

    STATUS_SUCCESS - to accept the connection
--*/
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext);
    UNREFERENCED_PARAMETER( ConnectionCookie );

    FLT_ASSERT( MiniSpyData.ClientPort == NULL );
    MiniSpyData.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}


VOID
SpyDisconnect(
    _In_opt_ PVOID ConnectionCookie
   )
/*++

Routine Description

    This is called when the connection is torn-down. We use it to close our handle to the connection

Arguments

    ConnectionCookie - unused

Return value

    None
--*/
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    //
    //  Close our handle
    //

    FltCloseClientPort( MiniSpyData.Filter, &MiniSpyData.ClientPort );
}

NTSTATUS
SpyFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is called when a request has been made to unload the filter.  Unload
    requests from the Operation System (ex: "sc stop minispy" can not be
    failed.  Other unload requests may be failed.

    You can disallow OS unload request by setting the
    FLTREGFL_DO_NOT_SUPPORT_SERVICE_STOP flag in the FLT_REGISTARTION
    structure.

Arguments:

    Flags - Flags pertinent to this operation

Return Value:

    Always success

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    //
    //  Close the server port. This will stop new connections.
    //

    FltCloseCommunicationPort( MiniSpyData.ServerPort );

    FltUnregisterFilter( MiniSpyData.Filter );

    SpyEmptyOutputBufferList();
    ExDeleteNPagedLookasideList( &MiniSpyData.FreeBufferList );
    return STATUS_SUCCESS;
}


NTSTATUS
SpyQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This allows our filter to be manually detached from a volume.

Arguments:

    FltObjects - Contains pointer to relevant objects for this operation.
        Note that the FileObject field will always be NULL.

    Flags - Flags pertinent to this operation

Return Value:

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    PAGED_CODE();
    return STATUS_SUCCESS;
}
PPROCESS_STATS GetList(PUNICODE_STRING Path) {
    PLIST_ENTRY entry;
    PPROCESS_STATS pStats = NULL;


    KeAcquireGuardedMutex(&g_StatsLock);


    for (entry = g_ProcessStatsList.Flink; entry != &g_ProcessStatsList; entry = entry->Flink) {
        PPROCESS_STATS candidate = CONTAINING_RECORD(entry, PROCESS_STATS, ListEntry);
        if (RtlEqualUnicodeString(Path, &candidate->ImagePath, TRUE)) {
            pStats = candidate;
            break;
        }
    }

    KeReleaseGuardedMutex(&g_StatsLock);
    return pStats;
}
BOOLEAN mP = FALSE;
BOOLEAN mD = FALSE;
LARGE_INTEGER sTime;
NTSTATUS
SpyMessage (
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
/*++

Routine Description:

    This is called whenever a user mode application wishes to communicate
    with this minifilter.

Arguments:

    ConnectionCookie - unused

    OperationCode - An identifier describing what type of message this
        is.  These codes are defined by the MiniFilter.
    InputBuffer - A buffer containing input data, can be NULL if there
        is no input data.
    InputBufferSize - The size in bytes of the InputBuffer.
    OutputBuffer - A buffer provided by the application that originated
        the communication in which to store data to be returned to this
        application.
    OutputBufferSize - The size in bytes of the OutputBuffer.
    ReturnOutputBufferSize - The size in bytes of meaningful data
        returned in the OutputBuffer.

Return Value:

    Returns the status of processing the message.

--*/
{
    MINISPY_COMMAND command;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    //
    //                      **** PLEASE READ ****
    //
    //  The INPUT and OUTPUT buffers are raw user mode addresses.  The filter
    //  manager has already done a ProbedForRead (on InputBuffer) and
    //  ProbedForWrite (on OutputBuffer) which guarentees they are valid
    //  addresses based on the access (user mode vs. kernel mode).  The
    //  minifilter does not need to do their own probe.
    //
    //  The filter manager is NOT doing any alignment checking on the pointers.
    //  The minifilter must do this themselves if they care (see below).
    //
    //  The minifilter MUST continue to use a try/except around any access to
    //  these buffers.
    //

    if ((InputBuffer != NULL) &&
        (InputBufferSize >= (FIELD_OFFSET(COMMAND_MESSAGE,Command) +
                             sizeof(MINISPY_COMMAND)))) {

        try  {

            //
            //  Probe and capture input message: the message is raw user mode
            //  buffer, so need to protect with exception handler
            //

            command = ((PCOMMAND_MESSAGE) InputBuffer)->Command;

        } except (SpyExceptionFilter( GetExceptionInformation(), TRUE )) {
        
            return GetExceptionCode();
        }

        switch (command) {
            case COMMAND_SWITCH_MODE:
                try {
                    PMINISPY_COMMAND_MSG msg = (PMINISPY_COMMAND_MSG)InputBuffer;
                    LARGE_INTEGER cTime;
                    KeQuerySystemTime(&cTime);
                    sTime = cTime;
                    if (msg->Mode == 1) {
                        if (mP == TRUE) {
                            mP = FALSE;
                        }
                        else {
                            mP = TRUE;
                        }
                        mD = FALSE;
                    }
                    else if (msg->Mode == 2) {
                        if (mD == TRUE) {
                            mD = FALSE;
                        }
                        else {
                            mD = TRUE;
                        }
                        mP = FALSE;
                    }
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status: mP:%u mD:%u\n", mP, mD);
                }except(SpyExceptionFilter(GetExceptionInformation(), TRUE)) {
                    status = GetExceptionCode();
                }
                status = STATUS_SUCCESS;
                break;

            case COMMAND_SIG_STATUS:
                try {
                    PMINISPY_COMMAND_MSG msg = (PMINISPY_COMMAND_MSG)InputBuffer;
                    PEPROCESS eProcess = NULL;
                    PUNICODE_STRING pPathName = NULL;
                    ULONG Pid = msg->PID;
                    INT IsSigned = msg->IsSigned;

                    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Pid, &eProcess))) {
                        if (NT_SUCCESS(SeLocateProcessImageName(eProcess, &pPathName)) && pPathName != NULL) {
                            PPROCESS_STATS test = GetList(pPathName);
                            test->IsSigned = IsSigned;
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Path1: %wZ ,Signed: %d\n", test->ImagePath, test->IsSigned);
                        }
                    }
                    
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "UHUHUHUHU\n");
                }except(SpyExceptionFilter(GetExceptionInformation(), TRUE)) {
                    status = GetExceptionCode();
                }

                status = STATUS_SUCCESS;
                break;
            case GetMiniSpyLog:

                //
                //  Return as many log records as can fit into the OutputBuffer
                //

                if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {

                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                //
                //  We want to validate that the given buffer is POINTER
                //  aligned.  But if this is a 64bit system and we want to
                //  support 32bit applications we need to be careful with how
                //  we do the check.  Note that the way SpyGetLog is written
                //  it actually does not care about alignment but we are
                //  demonstrating how to do this type of check.
                //

#if defined(_WIN64)

                if (IoIs32bitProcess( NULL )) {

                    //
                    //  Validate alignment for the 32bit process on a 64bit
                    //  system
                    //

                    if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                        status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

                } else {

#endif

                    if (!IS_ALIGNED(OutputBuffer,sizeof(PVOID))) {

                        status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

#if defined(_WIN64)

                }

#endif

                //
                //  Get the log record.
                //

                status = SpyGetLog( OutputBuffer,
                                    OutputBufferSize,
                                    ReturnOutputBufferLength );
                break;


            case GetMiniSpyVersion:

                //
                //  Return version of the MiniSpy filter driver.  Verify
                //  we have a valid user buffer including valid
                //  alignment
                //

                if ((OutputBufferSize < sizeof( MINISPYVER )) ||
                    (OutputBuffer == NULL)) {

                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                //
                //  Validate Buffer alignment.  If a minifilter cares about
                //  the alignment value of the buffer pointer they must do
                //  this check themselves.  Note that a try/except will not
                //  capture alignment faults.
                //

                if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                    status = STATUS_DATATYPE_MISALIGNMENT;
                    break;
                }

                //
                //  Protect access to raw user-mode output buffer with an
                //  exception handler
                //

                try {

                    ((PMINISPYVER)OutputBuffer)->Major = MINISPY_MAJ_VERSION;
                    ((PMINISPYVER)OutputBuffer)->Minor = MINISPY_MIN_VERSION;

                } except (SpyExceptionFilter( GetExceptionInformation(), TRUE )) {

                      return GetExceptionCode();
                }

                *ReturnOutputBufferLength = sizeof( MINISPYVER );
                status = STATUS_SUCCESS;
                break;

            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }

    } else {

        status = STATUS_INVALID_PARAMETER;
    }

    return status;
}


//---------------------------------------------------------------------------
//              Operation filtering routines
//---------------------------------------------------------------------------
BOOLEAN Prunning(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
) {
    PRECORD_LIST recordList;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    PUNICODE_STRING nameToUse;
    UNICODE_STRING unknownName = RTL_CONSTANT_STRING(L"UNKNOWN");

#if MINISPY_VISTA
    PUNICODE_STRING ecpDataToUse = NULL;
    UNICODE_STRING ecpData;
    WCHAR ecpDataBuffer[MAX_NAME_SPACE / sizeof(WCHAR)];
#endif

    recordList = SpyNewRecord();
    if (!recordList) {
        return FALSE;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    PEPROCESS pProcess = NULL;
    HANDLE ProcessId = (HANDLE)FltGetRequestorProcessId(Data);

    NTSTATUS nameStatus = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (NT_SUCCESS(nameStatus)) {
        PCHAR imageName = (PCHAR)PsGetProcessImageFileName(pProcess);
        RtlStringCbCopyA(recordList->LogRecord.Data.ProcessName, sizeof(recordList->LogRecord.Data.ProcessName), imageName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SendToUser Process: %s\n", imageName);
        ObDereferenceObject(pProcess);
    }
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS path = SeLocateProcessImageName(pProcess, &pImageName);
    if (NT_SUCCESS(path) && pImageName != NULL) {
        nameToUse = pImageName;
        ExFreePool(pImageName);
    }
    else {
        nameToUse = &unknownName;
    }
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;


#if MINISPY_VISTA

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        RtlInitEmptyUnicodeString(&ecpData,
            ecpDataBuffer,
            MAX_NAME_SPACE / sizeof(WCHAR));

        SpyParseEcps(Data, recordList, &ecpData);
        ecpDataToUse = &ecpData;
    }


    SpySetRecordNameAndEcpData(&(recordList->LogRecord), nameToUse, ecpDataToUse);
#else

    SpySetRecordName(&(recordList->LogRecord), nameToUse);
#endif

    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }
    recordList->LogRecord.Data.Status = Data->IoStatus.Status;
    SpyLogPreOperationData(Data, FltObjects, recordList);
    SpyLog(recordList);

    return TRUE;
}


BOOLEAN SendToUserSpace(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
) {
    PRECORD_LIST recordList;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    PUNICODE_STRING nameToUse;
    UNICODE_STRING unknownName = RTL_CONSTANT_STRING(L"UNKNOWN");

#if MINISPY_VISTA
    PUNICODE_STRING ecpDataToUse = NULL;
    UNICODE_STRING ecpData;
    WCHAR ecpDataBuffer[MAX_NAME_SPACE / sizeof(WCHAR)];
#endif

    recordList = SpyNewRecord();
    if (!recordList) {
        return FALSE;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    PEPROCESS pProcess = NULL;
    HANDLE ProcessId = (HANDLE)FltGetRequestorProcessId(Data);

    NTSTATUS nameStatus = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (NT_SUCCESS(nameStatus)) {
        PCHAR imageName = (PCHAR)PsGetProcessImageFileName(pProcess);
        RtlStringCbCopyA(recordList->LogRecord.Data.ProcessName, sizeof(recordList->LogRecord.Data.ProcessName), imageName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SendToUser Process: %s\n", imageName);
        ObDereferenceObject(pProcess);
    }
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS path = SeLocateProcessImageName(pProcess, &pImageName);
    if (NT_SUCCESS(path) && pImageName != NULL) {
        nameToUse = pImageName;
        ExFreePool(pImageName);
    }
    else {
        nameToUse = &unknownName;
    }


#if MINISPY_VISTA

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        RtlInitEmptyUnicodeString(&ecpData,
            ecpDataBuffer,
            MAX_NAME_SPACE / sizeof(WCHAR));

        SpyParseEcps(Data, recordList, &ecpData);
        ecpDataToUse = &ecpData;
    }


    SpySetRecordNameAndEcpData(&(recordList->LogRecord), nameToUse, ecpDataToUse);
#else

    SpySetRecordName(&(recordList->LogRecord), nameToUse);
#endif

    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }

    SpyLogPreOperationData(Data, FltObjects, recordList);
    SpyLog(recordList);

    return TRUE;
}


BOOLEAN Profiling(
    PUNICODE_STRING Path,
    OP_TYPE OpType,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    PLIST_ENTRY entry;
    PPROCESS_STATS pStats = NULL;
    LARGE_INTEGER currentTime;
    ULONG Topen = 0;
    ULONG Trename = 0;
    ULONG Tproc = 0;
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);


    KeQuerySystemTime(&currentTime);


    KeAcquireGuardedMutex(&g_StatsLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Mulai\n");
    for (entry = g_ProcessStatsList.Flink; entry != &g_ProcessStatsList; entry = entry->Flink) {
        PPROCESS_STATS candidate = CONTAINING_RECORD(entry, PROCESS_STATS, ListEntry);
        if (RtlEqualUnicodeString(Path, &candidate->ImagePath, TRUE)) {
            pStats = candidate;
            break;
        }
    }

    if (pStats == NULL) {
        pStats = (PPROCESS_STATS)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_STATS), 'stat');
        if (pStats) {
            RtlZeroMemory(pStats, sizeof(PROCESS_STATS));
            pStats->ImagePath.MaximumLength = Path->MaximumLength;
            pStats->ImagePath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, Path->MaximumLength, 'pstr');
            if (pStats->ImagePath.Buffer) {
                RtlCopyUnicodeString(&pStats->ImagePath, Path);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Path: %wZ\n", pStats->ImagePath);
            }
            pStats->LastResetTime = currentTime;
            InsertHeadList(&g_ProcessStatsList, &pStats->ListEntry);
        }
    }
    else {
        LONGLONG diff = currentTime.QuadPart - sTime.QuadPart;
        if (diff > 100000000) {
            for (entry = g_ProcessStatsList.Flink; entry != &g_ProcessStatsList; entry = entry->Flink) {
                PPROCESS_STATS candidate = CONTAINING_RECORD(entry, PROCESS_STATS, ListEntry);
                if (candidate->FileOpenCount > 0) {
                    Topen += candidate->FileOpenCount;
                }
                if (candidate->FileRenameCount > 0) {
                    Trename += candidate->FileRenameCount;
                }
                Tproc++;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "P ke: %d\n", Tproc);
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Topen: %d\n", Tproc);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Topen: %d\n", Topen);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Trename: %d\n", Trename);
            pStats->LastResetTime = currentTime;
            if (OpType == OP_TYPE_OPEN) {
                pStats->FileOpenCount = 0;
                pStats->FileRenameCount = 0;
            }
            else {
                pStats->FileOpenCount = 0;
                pStats->FileRenameCount = 0;
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KONTOOTMOT\n");
            mP = FALSE;
            mD = FALSE;
        }
        else {
            if (OpType == OP_TYPE_OPEN) {
                pStats->FileOpenCount++;
            }
            else if (OpType == OP_TYPE_RENAME) {
                pStats->FileRenameCount++;
            }
        }
    }

    KeReleaseGuardedMutex(&g_StatsLock);
    return TRUE;

}

BOOLEAN Check(
    PUNICODE_STRING Path,
    OP_TYPE OpType,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    PLIST_ENTRY entry;
    PPROCESS_STATS pStats = NULL;
    BOOLEAN isRansomware = FALSE;
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);


    KeAcquireGuardedMutex(&g_StatsLock);


    for (entry = g_ProcessStatsList.Flink; entry != &g_ProcessStatsList; entry = entry->Flink) {
        PPROCESS_STATS candidate = CONTAINING_RECORD(entry, PROCESS_STATS, ListEntry);
        if (RtlEqualUnicodeString(Path, &candidate->ImagePath, TRUE)) {
            pStats = candidate;
            break;
        }
    }

    if (pStats == NULL) {
        pStats = (PPROCESS_STATS)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_STATS), 'stat');
        if (pStats) {
            RtlZeroMemory(pStats, sizeof(PROCESS_STATS));
            pStats->ImagePath.MaximumLength = Path->MaximumLength;
            pStats->ImagePath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, Path->MaximumLength, 'pstr');
            if (pStats->ImagePath.Buffer) {
                RtlCopyUnicodeString(&pStats->ImagePath, Path);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Path: %wZ\n", pStats->ImagePath);
            }
            pStats->LastResetTime = currentTime;
            pStats->IsSigned = -1;
            //SendToUserSpace(Data, FltObjects);
            InsertHeadList(&g_ProcessStatsList, &pStats->ListEntry);
        }
    }
    else {
        LONGLONG diff = currentTime.QuadPart - pStats->LastResetTime.QuadPart;
        if (diff > RESET_INTERVAL_TICKS && pStats->IsSigned != -1) {

            pStats->LastResetTime = currentTime;
            if (OpType == OP_TYPE_OPEN) {
                pStats->FileOpenCount = 1;
                pStats->FileRenameCount = 0;
            }
            else {
                pStats->FileOpenCount = 0;
                pStats->FileRenameCount = 1;
            }
        }
        else {

            if (OpType == OP_TYPE_OPEN) {
                pStats->FileOpenCount++;
            }
            else if (OpType == OP_TYPE_RENAME) {
                pStats->FileRenameCount++;
            }
        }
        ULONG Fopen = (pStats->FileOpenCount * 100) / 50;
        if (Fopen > 100) Fopen = 100;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Fopen: %u\n", Fopen);
        ULONG Frename = (pStats->FileRenameCount * 100) / 5;
        if (Frename > 100) Frename = 100;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Frename: %u\n", Frename);
        if (pStats->IsSigned == 1) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Signature: 1 Path: %wZ\n", pStats->ImagePath);
        }else if(pStats->IsSigned == 0){
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Signature: 0 Path: %wZ\n", pStats->ImagePath);
        }
        if (pStats->FileOpenCount > MAX_FILE_OPENS_PER_SECOND ||
            pStats->FileRenameCount > MAX_FILE_RENAMES_PER_SECOND) {
            isRansomware = TRUE;
            pStats->FileOpenCount = 0;
            pStats->FileRenameCount = 0;
        }
    }
  


    KeReleaseGuardedMutex(&g_StatsLock);
    return isRansomware;
}

BOOLEAN IsProcessWhitelisted(ULONG ProcessId) {
    PEPROCESS pProcess = NULL;
    PUNICODE_STRING pImageName = NULL;
    BOOLEAN isSafe = FALSE;
    NTSTATUS status;
    PLIST_ENTRY entry;
    PWHITELIST_ENTRY pEntry;

    if (ProcessId <= 4) return TRUE;


    status = PsLookupProcessByProcessId((HANDLE)ProcessId, &pProcess);
    if (!NT_SUCCESS(status)) return FALSE;

    status = SeLocateProcessImageName(pProcess, &pImageName);

    


    if (NT_SUCCESS(status) && pImageName != NULL) {
        KeAcquireGuardedMutex(&g_WhitelistLock);
        for (entry = g_WhitelistHead.Flink; entry != &g_WhitelistHead; entry = entry->Flink) {
            pEntry = CONTAINING_RECORD(entry, WHITELIST_ENTRY, ListEntry);

            if (RtlEqualUnicodeString(pImageName, &pEntry->ImagePath, TRUE)) {
                isSafe = TRUE;
                break; 
            }
        }

        KeReleaseGuardedMutex(&g_WhitelistLock);
        ExFreePool(pImageName);
    }

    ObDereferenceObject(pProcess);
    return isSafe;
}

FLT_PREOP_CALLBACK_STATUS
SpyPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    ULONG ProcessId;
    ACCESS_MASK DesiredAccess;
    NTSTATUS nameStatus;


    ProcessId = FltGetRequestorProcessId(Data);
    PEPROCESS eProcess = NULL;
    PUNICODE_STRING pPathName = NULL;

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ProcessId, &eProcess))) {
        if (NT_SUCCESS(SeLocateProcessImageName(eProcess, &pPathName)) && pPathName != NULL) {
            if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {


                if (ProcessId <= 4) {
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }

                if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
                    //========================================================================================================
                    if (IsProcessWhitelisted(ProcessId)) {

                        return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                    if (mP == TRUE) {
                        if (Profiling(pPathName, OP_TYPE_RENAME, Data, FltObjects)) {
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                    else if (mD == TRUE) {
                        if (Check(pPathName, OP_TYPE_RENAME, Data, FltObjects)) {
                            PEPROCESS pProcess = NULL;
                            PCHAR procName = "Unknown";
                            nameStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &pProcess);
                            PPROCESS_STATS test = GetList(pPathName);
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Path1: %wZ\n", test->ImagePath);
                            if (NT_SUCCESS(nameStatus)) {

                                procName = (PCHAR)PsGetProcessImageFileName(pProcess);
                                HANDLE hProcess = NULL;
                                NTSTATUS termStatus;

                                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CoreSentinel: [BLOCK] MASS RENAME! Process: %s (PID: %d)\n", procName, ProcessId);
                                termStatus = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE, *PsProcessType, KernelMode, &hProcess);
                                if (NT_SUCCESS(termStatus)) {
                                    ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
                                    ZwClose(hProcess);
                                }

                                ObDereferenceObject(pProcess);
                            }
                            else {

                                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                    "CoreSentinel: [BLOCK] RANSOMWARE DETECTED! PID: %d\n", ProcessId);
                            }

                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            Data->IoStatus.Information = 0;
                            Prunning(Data, FltObjects);
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                }
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {


                if (ProcessId <= 4) {
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }
                DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

                BOOLEAN isWriteOperation = (DesiredAccess & (FILE_WRITE_DATA |
                    FILE_APPEND_DATA |
                    DELETE |
                    GENERIC_WRITE |
                    GENERIC_ALL)) != 0;

                if (!isWriteOperation) {
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }
                if (IsProcessWhitelisted(ProcessId)) {

                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }
                if (mP == TRUE) {
                    if (Profiling(pPathName, OP_TYPE_RENAME, Data, FltObjects)) {
                        return FLT_PREOP_COMPLETE;
                    }
                }
                else if (mD == TRUE) {
                    if (Check(pPathName, OP_TYPE_OPEN, Data, FltObjects)) {
                        PEPROCESS pProcess = NULL;
                        PCHAR procName = "Unknown";

                        nameStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &pProcess);
                        PPROCESS_STATS test = GetList(pPathName);
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Path2: %wZ\n", test->ImagePath);
                        if (NT_SUCCESS(nameStatus)) {
                            procName = (PCHAR)PsGetProcessImageFileName(pProcess);
                            HANDLE hProcess = NULL;
                            NTSTATUS termStatus;

                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CoreSentinel: [BLOCK] MASS OPEN! Process: %s (PID: %d)\n", procName, ProcessId);
                            termStatus = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE, *PsProcessType, KernelMode, &hProcess);
                            if (NT_SUCCESS(termStatus)) {
                                ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
                                ZwClose(hProcess);
                            }

                            ObDereferenceObject(pProcess);
                        }
                        else {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                "CoreSentinel: [BLOCK] RANSOMWARE DETECTED! PID: %d\n", ProcessId);
                        }

                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        Prunning(Data, FltObjects);
                        return FLT_PREOP_COMPLETE;
                    }
                }

            }
            ExFreePool(pPathName);
        }
        ObDereferenceObject(eProcess);
    }



    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
SpyEnlistInTransaction (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
/*++

Routine Description

    Minispy calls this function to enlist in a transaction of interest. 

Arguments

    FltObjects - Contains parameters required to enlist in a transaction.

Return value

    Returns STATUS_SUCCESS if we were able to successfully enlist in a new transcation or if we
    were already enlisted in the transaction. Returns an appropriate error code on a failure.
    
--*/
{

#if MINISPY_VISTA

    PMINISPY_TRANSACTION_CONTEXT transactionContext = NULL;
    PMINISPY_TRANSACTION_CONTEXT oldTransactionContext = NULL;
    PRECORD_LIST recordList;
    NTSTATUS status;
    static ULONG Sequence=1;

    //
    //  This code is only built in the Vista environment, but
    //  we need to ensure this binary still runs down-level.  Return
    //  at this point if the transaction dynamic imports were not found.
    //
    //  If we find FltGetTransactionContext, we assume the other
    //  transaction APIs are also present.
    //

    if (NULL == MiniSpyData.PFltGetTransactionContext) {

        return STATUS_SUCCESS;
    }

    //
    //  Try to get our context for this transaction. If we get
    //  one we have already enlisted in this transaction.
    //

    status = (*MiniSpyData.PFltGetTransactionContext)( FltObjects->Instance,
                                                       FltObjects->Transaction,
                                                       &transactionContext );

    if (NT_SUCCESS( status )) {

        // 
        //  Check if we have already enlisted in the transaction. 
        //

        if (FlagOn(transactionContext->Flags, MINISPY_ENLISTED_IN_TRANSACTION)) {

            //
            //  FltGetTransactionContext puts a reference on the context. Release
            //  that now and return success.
            //
            
            FltReleaseContext( transactionContext );
            return STATUS_SUCCESS;
        }

        //
        //  If we have not enlisted then we need to try and enlist in the transaction.
        //
        
        goto ENLIST_IN_TRANSACTION;
    }

    //
    //  If the context does not exist create a new one, else return the error
    //  status to the caller.
    //

    if (status != STATUS_NOT_FOUND) {

        return status;
    }

    //
    //  Allocate a transaction context.
    //

    status = FltAllocateContext( FltObjects->Filter,
                                 FLT_TRANSACTION_CONTEXT,
                                 sizeof(MINISPY_TRANSACTION_CONTEXT),
                                 PagedPool,
                                 &transactionContext );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Set the context into the transaction
    //

    RtlZeroMemory(transactionContext, sizeof(MINISPY_TRANSACTION_CONTEXT));
    transactionContext->Count = Sequence++;

    FLT_ASSERT( MiniSpyData.PFltSetTransactionContext );

    status = (*MiniSpyData.PFltSetTransactionContext)( FltObjects->Instance,
                                                       FltObjects->Transaction,
                                                       FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                                       transactionContext,
                                                       &oldTransactionContext );

    if (!NT_SUCCESS( status )) {

        FltReleaseContext( transactionContext );    //this will free the context

        if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

            return status;
        }

        FLT_ASSERT(oldTransactionContext != NULL);
        
        if (FlagOn(oldTransactionContext->Flags, MINISPY_ENLISTED_IN_TRANSACTION)) {

            //
            //  If this context is already enlisted then release the reference
            //  which FltSetTransactionContext put on it and return success.
            //
            
            FltReleaseContext( oldTransactionContext );
            return STATUS_SUCCESS;
        }

        //
        //  If we found an existing transaction then we should try and
        //  enlist in it. There is a race here in which the thread 
        //  which actually set the transaction context may fail to 
        //  enlist in the transaction and delete it later. It might so
        //  happen that we picked up a reference to that context here
        //  and successfully enlisted in that transaction. For now
        //  we have chosen to ignore this scenario.
        //

        //
        //  If we are not enlisted then assign the right transactionContext
        //  and attempt enlistment.
        //

        transactionContext = oldTransactionContext;            
    }

ENLIST_IN_TRANSACTION: 

    //
    //  Enlist on this transaction for notifications.
    //

    FLT_ASSERT( MiniSpyData.PFltEnlistInTransaction );

    status = (*MiniSpyData.PFltEnlistInTransaction)( FltObjects->Instance,
                                                     FltObjects->Transaction,
                                                     transactionContext,
                                                     FLT_MAX_TRANSACTION_NOTIFICATIONS );

    //
    //  If the enlistment failed we might have to delete the context and remove
    //  our count.
    //

    if (!NT_SUCCESS( status )) {

        //
        //  If the error is that we are already enlisted then we do not need
        //  to delete the context. Otherwise we have to delete the context
        //  before releasing our reference.
        //
        
        if (status == STATUS_FLT_ALREADY_ENLISTED) {

            status = STATUS_SUCCESS;

        } else {

            //
            //  It is worth noting that only the first caller of
            //  FltDeleteContext will remove the reference added by
            //  filter manager when the context was set.
            //
            
            FltDeleteContext( transactionContext );
        }
        
        FltReleaseContext( transactionContext );
        return status;
    }

    //
    //  Set the flag so that future enlistment efforts know that we
    //  successfully enlisted in the transaction.
    //

    SetFlagInterlocked( &transactionContext->Flags, MINISPY_ENLISTED_IN_TRANSACTION );
    
    //
    //  The operation succeeded, remove our count
    //

    FltReleaseContext( transactionContext );

    //
    //  Log a record that a new transaction has started.
    //

    recordList = SpyNewRecord();

    if (recordList) {

        SpyLogTransactionNotify( FltObjects, recordList, 0 );

        //
        //  Send the logged information to the user service.
        //

        SpyLog( recordList );
    }

#endif // MINISPY_VISTA

    return STATUS_SUCCESS;
}


#if MINISPY_VISTA

NTSTATUS
SpyKtmNotificationCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG TransactionNotification
    )
{
    PRECORD_LIST recordList;

    UNREFERENCED_PARAMETER( TransactionContext );

    //
    //  Try and get a log record
    //

    recordList = SpyNewRecord();

    if (recordList) {

        SpyLogTransactionNotify( FltObjects, recordList, TransactionNotification );

        //
        //  Send the logged information to the user service.
        //

        SpyLog( recordList );
    }

    return STATUS_SUCCESS;
}

#endif // MINISPY_VISTA

VOID
SpyDeleteTxfContext (
    _Inout_ PMINISPY_TRANSACTION_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    UNREFERENCED_PARAMETER( Context );
    UNREFERENCED_PARAMETER( ContextType );

    FLT_ASSERT(FLT_TRANSACTION_CONTEXT == ContextType);
    FLT_ASSERT(Context->Count != 0);
}


LONG
SpyExceptionFilter (
    _In_ PEXCEPTION_POINTERS ExceptionPointer,
    _In_ BOOLEAN AccessingUserBuffer
    )
/*++

Routine Description:

    Exception filter to catch errors touching user buffers.

Arguments:

    ExceptionPointer - The exception record.

    AccessingUserBuffer - If TRUE, overrides FsRtlIsNtStatusExpected to allow
                          the caller to munge the error to a desired status.

Return Value:

    EXCEPTION_EXECUTE_HANDLER - If the exception handler should be run.

    EXCEPTION_CONTINUE_SEARCH - If a higher exception handler should take care of
                                this exception.

--*/
{
    NTSTATUS Status;

    Status = ExceptionPointer->ExceptionRecord->ExceptionCode;

    //
    //  Certain exceptions shouldn't be dismissed within the namechanger filter
    //  unless we're touching user memory.
    //

    if (!FsRtlIsNtstatusExpected( Status ) &&
        !AccessingUserBuffer) {

        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_EXECUTE_HANDLER;
}


