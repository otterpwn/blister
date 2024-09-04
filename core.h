#pragma once

#include <ntddk.h>

VOID ImageLoadNotifyCallback(IN OPTIONAL PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);
VOID ReportCallbacks(IN PVOID StartContext);
VOID PCreateProcessNotifyRoutineEx(IN OUT PEPROCESS Process, IN HANDLE ProcessId, IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo);
OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);