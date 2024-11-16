#include <ntddk.h>
#include <aux_klib.h>
#include <Ntstrsafe.h>

#include "customTypes.h"
#include "macros.h"

extern BlisterState driverState;

// function to log callbacks and the driver that owns them
VOID ReportCallbacks(IN PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);

    NTSTATUS returnStatus;
    AUX_MODULE_EXTENDED_INFO* kernelModuleList = NULL;
    PVOID* callbackAddresses = NULL;
    SIZE_T totalCallbacks = 0;
    SIZE_T maxCallbacks = 10;

    // allocate the heap object to hold the hold 10 entries
    callbackAddresses = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PVOID) * maxCallbacks, 'blCr');
    if (callbackAddresses == NULL) {
        ERROR("Failed to allocate heap memory for cache of callback addresses\n");
        goto MemoryCleanup;
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
        PLIST_ENTRY currentCallbackListEntry = callbackList->Flink;

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

                PVOID* newCallbackAddresses = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PVOID) * maxCallbacks, 'blCr');

                // check if the array was allocated properly
                if (newCallbackAddresses == NULL) {
                    ERROR("Failed to expand cache for callback addresses\n");
                    goto MemoryCleanup;
                }

                // if everything worked we can copy the old array into the new
                // one, free the heap pool allocated for the old array and update the pointer
                // to the first element
                RtlCopyMemory(newCallbackAddresses, callbackAddresses, sizeof(PVOID) * totalCallbacks);
                ExFreePoolWithTag(callbackAddresses, 'blCr');
                callbackAddresses = newCallbackAddresses;
            }

            // only after we're sure the array as enough space
            // we can move to the next entry
            currentCallbackListEntry = currentCallbackListEntry->Flink;
        }

        // once we're done enumerating the callback list
        // we can revert the changes by releasing the lock
		// and re-enabling the APCs
        ExReleasePushLockExclusive(&psProcess->TypeLock);
        KeLeaveCriticalRegion();
    }

    // now that we have an array of callback addresses
    // we can enumerate them to find the driver that owns every single one

    // since we don't really know the size our buffer needs to be
    // we can use the AuxKlibQueryModuleInformation with a
    // buffer size of 0 and a NUL QueryInfo array
    // "If this [QueryInfo] pointer is NULL, AuxKlibQueryModuleInformation writes the required buffer size to the location that BufferSize points to."
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/aux_klib/nf-aux_klib-auxklibquerymoduleinformation  
    ULONG bufferSizeToAllocate = 0;
    returnStatus = AuxKlibInitialize();

    if (!NT_SUCCESS(returnStatus)) {
        ERROR("Failed to initialize AuxKlib\n");
        goto MemoryCleanup;
    }

    returnStatus = AuxKlibQueryModuleInformation(&bufferSizeToAllocate, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);

    // if the buffer size is still 0 it means that the AuxKlibQueryModuleInformation
    // function couldn't manage to calculate the required buffer size
    // for the kernel modules to enumerate
    if (!NT_SUCCESS(returnStatus) || bufferSizeToAllocate == 0) {
        WARN("Failed to determine buffer size for AuxKlibQueryModuleInformation");
        goto MemoryCleanup;
    }

    ULONG totalKernelModules = bufferSizeToAllocate / sizeof(AUX_MODULE_EXTENDED_INFO);
    kernelModuleList = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSizeToAllocate, 'blCr');

    if (kernelModuleList == NULL) {
        ERROR("Failed to allocate buffer for list of kernel modules\n");
        goto MemoryCleanup;
    }

    // at this point we can query the system information
    // for each module and add it to the list
    // this time the AuxKlibQueryModuleInformation will function properly
    // since we supply a buffer size != 0 and a QueryInfo pointer != NULL
    RtlZeroMemory(kernelModuleList, bufferSizeToAllocate);
    returnStatus = AuxKlibQueryModuleInformation(&bufferSizeToAllocate, sizeof(AUX_MODULE_EXTENDED_INFO), kernelModuleList);
 
    if (!NT_SUCCESS(returnStatus)) {
        WARN("Failed to obtain kernel modules");
        goto MemoryCleanup;
    }

    // iterate over the list of callback addresses
    // and find their owning modules from the list of kernel modules
    for (SIZE_T o = 0; o < totalCallbacks; o++) {
        BOOLEAN matched = FALSE;
        PVOID callbackAddress = callbackAddresses[o];

        // iterate over the modules list
        for (ULONG t = 0; t < totalKernelModules; t++) {
            // here we get the current kernel module in the list
            // get the base address and size from the object
            // and check if the address of the callback we're looking for
            // is between the base address and baseAddress + sizeofModule
            // Get the current module
            AUX_MODULE_EXTENDED_INFO* currentModule = &kernelModuleList[t];
            PVOID currentModuleBase = currentModule->BasicInfo.ImageBase;
            ULONG currentModuleSize = currentModule->ImageSize;

            if (callbackAddress >= currentModuleBase && callbackAddress < (PVOID)((ULONG_PTR)currentModuleBase + currentModuleSize)) {
                matched = TRUE;
                SUCCESS("The callback address %p is owned by %s", callbackAddress, currentModule->FullPathName);
                break;
            }
        }
        if (!matched) {
            WARN("Callback address %p has no owner kernel module (???)\n", callbackAddress);
        }
    }
    goto MemoryCleanup;



MemoryCleanup:
    if (callbackAddresses != NULL) { ExFreePoolWithTag(callbackAddresses, 'blCr'); }
    if (kernelModuleList != NULL) { ExFreePoolWithTag(kernelModuleList, 'blCr'); }
    return;
}

OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    HANDLE targetPid;
    HANDLE sourcePid;
    BOOLEAN isPP = FALSE;
    
    // get a handle to the first PID
    if (OperationInformation->ObjectType != *PsProcessType) {
		// handle a different callee object type
        goto Cleanup;
    }
    PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = PsGetProcessId(OpenedProcess);
    sourcePid = PsGetCurrentProcessId();

    // if the target process is trying to open a handle
    // to iteself, we can skip the rest of the implementation
    if (targetPid == sourcePid || OpenedProcess == PsGetCurrentProcess()) {
        goto Cleanup;
    }

    // search for the PID in the cached PIDs from the driverState object (BlisterState->CacheSelfProtectedPIDs)
    // if we find a match, we can break the loop
	// @reference: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-interlockedcompareexchange64
    for (int o = 0; o < NUMBEROFELEMENTS(driverState.CacheSelfProtectedPIDs); o++) {
        HANDLE intelockedCompareResult = (HANDLE)InterlockedCompareExchange64(&(LONG64)driverState.CacheSelfProtectedPIDs[o], 0, 0);
        
        if (intelockedCompareResult == targetPid && OperationInformation->KernelHandle != TRUE) {
            isPP = TRUE;
            break;
        }
    }

    if (!isPP) {
        goto Cleanup;
    }

    if (isPP) {
        INFO("A process is trying to get a handle to the PP %d from a PID of ^%d, blocking the operation\n", targetPid, sourcePid);
        // if the protected process is getting accessed by another process
        // (create handle or duplicate handle) strip the handle
        // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_create_handle_information
        ACCESS_MASK denyAccessToHandle = PROCESS_TERMINATE;

        switch (OperationInformation->Operation) {
        case OB_OPERATION_HANDLE_CREATE:
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~denyAccessToHandle;
            break;
        case OB_OPERATION_HANDLE_DUPLICATE:
            break;
        }
    }

Cleanup:
    return OB_PREOP_SUCCESS;
}

// todo: understand how this works
VOID ImageLoadNotifyCallback(IN OPTIONAL PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo) {
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    return;
}

VOID PcreateProcessNotifyExitingHandler(IN OUT PEPROCESS Process, IN HANDLE ProcessId, IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(CreateInfo);

    // since this function handles the callbacks from
    // PsSetCreateProcessNotifyRoutineEx when a process is exiting
    // we'll iterate over the list of active PPs and remove
    // the entry for the exiting process
    // the functionality will be really similar to the MemoryCleanup label 
    // and main while loop for the PCreateProcessNotifyRoutineEx
    // function but instead of copying the unicode string into new buffers
    // we'll be freeing the buffers instead


    // acquire the lock on the list and start
    // looping through the list
    KeAcquireGuardedMutex(&driverState.Lock);
    INFO("PCreateProcessNotifyExitingHandler successfully acquired a lock\n");

    PLIST_ENTRY startEntry = &driverState.SelfProtectedProcesses;
    PLIST_ENTRY nextEntry = startEntry->Flink;

    while (nextEntry != startEntry) {
        PProtectedProcessEntry ppEntry = CONTAINING_RECORD(nextEntry, ProtectedProcessEntry, CurEntry);

        // if the PID matches, remove everything related to the entry
        if (ppEntry->ProcessId == ProcessId) {
            if (ppEntry->Name != NULL) {
                if (ppEntry->Name->Buffer != NULL) {
                    ExFreePoolWithTag(ppEntry->Name->Buffer, 'blCr');
                }
                ExFreePoolWithTag(ppEntry->Name, 'blCr');
            }

            // remove the entry from the list
            RemoveEntryList(&ppEntry->CurEntry);


            // find the entry in the cached PIDs handles, set it to 0
            // and clean up the un-used entry as well
            for (int o = 0; o < NUMBEROFELEMENTS(driverState.CacheSelfProtectedPIDs); o++) {
                HANDLE hProcess = (HANDLE)InterlockedCompareExchange64(&(LONG64)driverState.CacheSelfProtectedPIDs[o], 0, (LONG64)ProcessId);
                
                if (hProcess == ProcessId) {
                    break;
                }
            }

            ExFreePoolWithTag(ppEntry, 'blCr');
            goto Cleanup;
        }

        // go forward in the list
        nextEntry = nextEntry->Flink;
    }

Cleanup:
    // release the lock
    KeReleaseGuardedMutex(&driverState.Lock);
    return;
}

VOID PcreateProcessNotifyRoutineEx(IN OUT PEPROCESS Process, IN HANDLE ProcessId, IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);

    PActiveProtectedProcessEntry ppEntry = NULL;

	// if CreateInfo is NULL it means the process is exiting
    // so we return before cleanup since no memory was allocated
    // and we haven't acquired any locks
    if (CreateInfo == NULL) {
        PcreateProcessNotifyExitingHandler(Process, ProcessId, CreateInfo);
        return;
    }
    INFO("CreateInfo is not NULL, process is not exiting\n");

    // if we get to this point it means that the process
    // callback is starting and we need to figure out
    // whether we need to protect the process or not

	// enumerate the SelfProtectedProcesses list
    // so we have to get a lock on it
    // and only then we can iterate over the list
    KeAcquireGuardedMutex(&driverState.Lock);
    INFO("PCreateProcessNotifyRoutineEx successfully acquired a lock");

    PLIST_ENTRY startEntry = &driverState.SelfProtectedProcesses;
    PLIST_ENTRY nextEntry = startEntry->Flink;

    // this is from GPT, apparently we need to skip the first entry
    // because it's not actualle part of the entries (?)
    while (nextEntry != startEntry) {
        PProtectedProcessEntry listEntry = CONTAINING_RECORD(nextEntry, ProtectedProcessEntry, CurEntry);
       
		// this horrible piece of code is to split CreateInfo->ImageFileName at the last slash
		// by iterating over the string backwards until we find a '/' or a '\'
        UNICODE_STRING imageName;
        imageName.Buffer = CreateInfo->ImageFileName->Buffer;
        imageName.Length = CreateInfo->ImageFileName->Length;
        imageName.MaximumLength = CreateInfo->ImageFileName->MaximumLength;

        for (int o = imageName.Length / sizeof(WCHAR); o > 0; o--) {
            if (imageName.Buffer[o] == L'\\' || imageName.Buffer[o] == L'/') {
                imageName.Buffer = &imageName.Buffer[o + 1];
                imageName.Length = (USHORT)(imageName.Length - (o + 1) * sizeof(WCHAR));
                imageName.MaximumLength = (USHORT)(imageName.MaximumLength - (o + 1) * sizeof(WCHAR));
                break;
            }
        }

        // now compare the isolated image names
        INFO("Comparing imageName entry %wZ to protected imageName entry %wZ\n", imageName, listEntry->Name);

        // if we find a match
        if (RtlCompareUnicodeString(&imageName, listEntry->Name, TRUE) == 0) {
            // now we allocate all the buffers for the PP entry and all its fields
            // allocate a buffer for the PP entry
            // allocate space for the name of the PP entry
            // allocate space for the name buffer with the name length
            ppEntry = (PActiveProtectedProcessEntry)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ActiveProtectedProcessEntry), 'blCr');
            if (ppEntry == NULL) {
                // exit if we can't allocate the space for the PP entry
                goto MemoryCleanup;

            }

            ppEntry->Name = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UNICODE_STRING), 'blCr');
            if (ppEntry->Name == NULL) {
                // exit if we can't allocate space for the name of the entry
                goto MemoryCleanup;
            }

            ppEntry->Name->Buffer = ExAllocatePool2(POOL_FLAG_PAGED, CreateInfo->ImageFileName->Length, 'blCr');
            if (ppEntry->Name->Buffer == NULL) {
                // exit if we can't allocate the space for the name buffer
                goto MemoryCleanup;
            }

            ppEntry->Name->MaximumLength = CreateInfo->ImageFileName->Length;

            // now that we allocated all the buffers we can
            // copy the image name string into the ppEntry object
            NTSTATUS ntStatus = RtlUnicodeStringCopy(ppEntry->Name, CreateInfo->ImageFileName);

            if (!NT_SUCCESS(ntStatus)) {
                // exit if the copy didn't work
                goto EndOfFunction;
            }

            // insert the protected process entry
            // into our list of active protected processes
            // and its PID in the cache of handles (if there is any space left)
            ppEntry->ProcessId = ProcessId;
            InsertTailList(&driverState.ActiveSelfProtectedProcesses, &ppEntry->CurEntry);

            for (int o = 0; o < NUMBEROFELEMENTS(driverState.CacheSelfProtectedPIDs); o++) {
                HANDLE interlockedCompareResult = (HANDLE)InterlockedCompareExchange64(&(LONG64)driverState.CacheSelfProtectedPIDs[o], (LONG64)ProcessId, 0);
                if (interlockedCompareResult == 0) {
                    break;
                }
            }

            goto EndOfFunction;
        }

        // advance to the next entry in the list
        nextEntry = nextEntry->Flink;
    }

MemoryCleanup:
    // free all the buffers we allocated for the PP entry
    // its name and the buffer for the name
    if (ppEntry != NULL) {
        if (ppEntry->Name != NULL) {
            if (ppEntry->Name->Buffer != NULL) {
                ExFreePoolWithTag(ppEntry->Name->Buffer, 'blCr');
            }
            ExFreePoolWithTag(ppEntry->Name, 'blCr');
        }
        ExFreePoolWithTag(ppEntry, 'blCr');
    }


EndOfFunction:
    // release the lock
    KeReleaseGuardedMutex(&driverState.Lock);
    return;
}