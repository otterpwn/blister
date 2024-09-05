#include <ntddk.h>
#include <aux_klib.h>

#include "customTypes.h"
#include "macros.h"

// @reference https://www.vergiliusproject.com/kernels/x64/windows-10/21h2/_OBJECT_TYPE_INITIALIZER
// THIS STRUCTURE CAN CHANGE BASED ON THE KERNEL VERSION
typedef struct _OBJECT_TYPE_INITIALIZER {
    uint16_t Length;
    union
    {
        uint16_t ObjectTypeFlags;
        struct
        {
            union
            {
                uint8_t CaseInsensitive;
                uint8_t UnnamedObjectsOnly;
                uint8_t UseDefaultObject;
                uint8_t SecurityRequired;
                uint8_t MaintainHandleCount;
                uint8_t MaintainTypeList;
                uint8_t SupportsObjectCallbacks;
                uint8_t CacheAligned;
            } __bitfield2;
            union
            {
                uint8_t UseExtendedParameters;
                uint8_t Reserved;
            } __bitfield3;
        } __inner1;
    } __inner1;
    uint32_t ObjectTypeCode;
    uint32_t InvalidAttributes;
    struct _GENERIC_MAPPING GenericMapping;
    uint32_t ValidAccessMask;
    uint32_t RetainAccess;
    enum _POOL_TYPE PoolType;
    uint32_t DefaultPagedPoolCharge;
    uint32_t DefaultNonPagedPoolCharge;
    void* DumpProcedure;
    int32_t* OpenProcedure;
    void* CloseProcedure;
    void* DeleteProcedure;
    union
    {
        int32_t* ParseProcedure;
        int32_t* ParseProcedureEx;
    } __inner14;
    int32_t* SecurityProcedure;
    int32_t* QueryNameProcedure;
    uint8_t* OkayToCloseProcedure;
    uint32_t WaitObjectFlagMask;
    uint16_t WaitObjectFlagOffset;
    uint16_t WaitObjectPointerOffset;
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _OB_CALLBACK_CONTEXT_BLOCK {
    LIST_ENTRY CallbackListEntry;
    OB_OPERATION Operations;
    ULONG Flags;
    PVOID Registration;
    POBJECT_TYPE ObjectType;
    PVOID PreCallback;
    PVOID PostCallback;
    EX_RUNDOWN_REF RundownReference;
} OB_CALLBACK_CONTEXT_BLOCK, *POB_CALLBACK_CONTEXT_BLOCK;

typedef struct _OBJECT_TYPE {
    struct _LIST_ENTRY TypeList;
    struct _UNICODE_STRING Name;
    void* DefaultObject;
    uint8_t Index;
    uint32_t TotalNumberOfObjects;
    uint32_t TotalNumberOfHandles;
    uint32_t HighWaterNumberOfObjects;
    uint32_t HighWaterNumberOfHandles;
    char _3C[4];
    struct _OBJECT_TYPE_INITIALIZER TypeInfo;
    EX_PUSH_LOCK TypeLock;
    uint32_t Key;
    char _C4[4];
    struct _LIST_ENTRY CallbackList;
} OBJECT_TYPE, *POBJECT_TYPE;


// function to log callbacks and the driver that owns them
VOID ReportCallbacks(IN PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);
    NTSTATUS returnStatus = STATUS_ABANDONED;
    SIZE_T totalCallbacks = 0;
    SIZE_T maxCallbacks = 10;
    AUX_MODULE_EXTENDED_INFO* moduleList = NULL;
    PVOID* callbackAddresses = NULL;

    // allocate the heap object to hold the hold 10 entries with tag blCh (blisterCache)
    callbackAddresses = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PVOID) * maxCallbacks, 'blCh');

    if (callbackAddresses == NULL) {
        ERROR("Failed to allocate heap memory for cache of callback addresses\n");
    }

    // find the callback table for different kinds of callbacks
    // everytime we enumerate the table we'll need to acquire a lock
    // for it to avoid memory corruption
    {
        // enumerate the PsProcessType callbacks
        POBJECT_TYPE psProcess = *PsProcessType;

        // obtain the lock on the callback table
        KeEnterCriticalRegion();                            // disable APCs
        ExAcquirePushLockExclusive(&psProcess->TypeLock);   // acquire the lock

        // parse the callback list and get the current / first element
        PLIST_ENTRY callbackList = &psProcess->CallbackList;
        PLIST_ENTRY currentCallbackListEntry = &callbackList->Flink;

        // iterate over the list
        while (currentCallbackListEntry != callbackList) {
            // here we will get the callback block, the callback address and add it to the array
            // and increment the total number of callbacks
            POB_CALLBACK_CONTEXT_BLOCK callbackBlock = CONTAINING_RECORD(currentCallbackListEntry, OB_CALLBACK_CONTEXT_BLOCK, CallbackListEntry);
            PVOID callbackAddress = callbackBlock->PreCallback;
            callbackAddresses[totalCallbacks] = callbackAddress;
            totalCallbacks++;

            // check if the array is full (10 entries)
            // if it is, reallocate it with twice the capacity
            if (totalCallbacks == maxCallbacks) {
                maxCallbacks *= 2;

                PVOID* newCallbackAddresses = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PVOID) * maxCallbacks, 'blCh');

                // check if the array was allocated properly
                if (newCallbackAddresses == NULL) {
                    ERROR("Failed to expand cache for callback addresses\n");
                }

                // if everything worked we can copy the old array into the new
                // one, free the heap pool allocated for the old array and update the pointer
                // to the first element
                RtlCopyMemory(newCallbackAddresses, callbackAddress, sizeof(PVOID) * totalCallbacks);
                ExFreePoolWithTag(callbackAddress, 'blCh');
                callbackAddress = newCallbackAddresses;
            }

            // only after we're sure the array has enough space
            // we can move to the next entry
            currentCallbackListEntry = currentCallbackListEntry->Flink;
        }
         
        // once we're done enumerating the callback list
        // we can revert the changes by releasing the lock
        // and re-enabling APCs
        ExReleasePushLockExclusive(&psProcess->TypeLock);
        KeLeaveCriticalRegion();
    }
}