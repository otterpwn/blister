#include <ntddk.h>

#include "customTypes.h"
#include "macros.h"

// function and globals definitions
DRIVER_UNLOAD UnloadDriver;
VOID ImageLoadNotifyCallback(IN OPTIONAL PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);
VOID ReportCallbacks(IN PVOID StartContext);
VOID PCreateProcessNotifyRoutineEx(IN OUT PEPROCESS Process, IN HANDLE ProcessId, IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo);
OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);

BlisterState driverState = { 0 };

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS returnStatus = NULL;
    //HANDLE hThread = NULL;
    UNICODE_STRING altitudeString;
    OB_CALLBACK_REGISTRATION obOpenProcPre = { 0 };

    //DriverObject->DriverUnload = UnloadDriver;

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
    }
    
    // mark the callback as registered in the driver status structure
    driverState.Callbacks.ImageLoadNotify.IsRegistered = TRUE;

    // set the CreateProcessNotify pointer in the driver callbacks to the
    // pointer of the PCreateProcessNotifyRoutineEx function and set it with
    // PsSetCreateProcessNotifyRoutineEx
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutineex
    driverState.Callbacks.ProcessNotify.CreateProcessNotifyPtr = PCreateProcessNotifyRoutineEx;
    returnStatus = PsSetCreateProcessNotifyRoutineEx(driverState.Callbacks.ProcessNotify.CreateProcessNotifyPtr, FALSE);

    if (!NT_SUCCESS(returnStatus)) {
        ERROR("PsSetCreateProcessNotifyRoutineEx failed to set PCreateProcessNotifyRoutineEx callback\n");
    }

    // mark the callback as registered in the driver status structure
    driverState.Callbacks.ProcessNotify.IsRegistered = TRUE;

    // set the OpenProcessNotify callback
    // using the ObRegisterCallbacks function
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks
    obOpenProcPre.Version = OB_FLT_REGISTRATION_VERSION;    // default version
    obOpenProcPre.OperationRegistrationCount = 1;           // only one entry

    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers#types-of-load-order-groups-and-their-altitude-ranges
    RtlInitUnicodeString(&altitudeString, L"423851");       // initialize the altitude string to the FIlter Load order group
    obOpenProcPre.Altitude = altitudeString;
    obOpenProcPre.RegistrationContext = NULL;

    // allocate the OperationRegistration field with the blCb (blisterCallback) tag
    // @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2
    obOpenProcPre.OperationRegistration = (POB_OPERATION_REGISTRATION)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(OB_OPERATION_REGISTRATION), 'blCb');

    // check if the buffer was succesfully allocated
    if (obOpenProcPre.OperationRegistration == NULL) {
        returnStatus = STATUS_UNSUCCESSFUL;
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
    }

    // mark the callback as registered in the driver status structure
    driverState.Callbacks.ProcessNotify.IsRegistered = TRUE;

	return STATUS_SUCCESS;
}

VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    PAGED_CODE();

    if (deviceObject != NULL) {
        IoDeleteDevice(deviceObject);
    }
}