#include <ntddk.h>

#include "customTypes.h"
#include "macros.h"

// function and globals definitions
DRIVER_UNLOAD UnloadDriver;
VOID ImageLoadNotifyCallback(IN OPTIONAL PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);
VOID ReportCallbacks(IN PVOID StartContext);
VOID PCreateProcessNotifyRoutineEx(IN OUT PEPROCESS Process, IN HANDLE ProcessId, IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo);
OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);

BlisterState CurrentDriverState = { 0 };

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS returnStatus = NULL;
    HANDLE hThread = NULL;
    OB_CALLBACK_REGISTRATION obOpenProcPre = { 0 };

    INFO("blister has started\n");

    // initialize a mutex and protected process lists
    // since CurrentDriverState is a global variable and multiple functions / threads 
    // can access, read and modify the members of the structure concurrenty
    // we need to initialize the Lock guarded mutex (KGUARDED_MUTEX)
    KeInitializeGuardedMutex(&CurrentDriverState.InUse);
    InitializeListHead(&CurrentDriverState.SelfProtectedProcesses);
    InitializeListHead(&CurrentDriverState.ActiveSelfProtectedProcesses);

    INFO("mutex and list initialzied properly\n");

	return STATUS_SUCCESS;
}

VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    PAGED_CODE();

    if (deviceObject != NULL) {
        IoDeleteDevice(deviceObject);
    }
}