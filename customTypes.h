#pragma once

#include <ntddk.h>

#define uint8_t         unsigned char
#define uint16_t        unsigned short
#define uint32_t        unsigned int
#define uint64_t        unsigned long long
#define int8_t          char
#define int16_t         short
#define int32_t         int
#define int64_t         long long


// process-specific access masks
// @reference https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
#define PROCESS_TERMINATE (0x0001)
#define PROCESS_CREATE_THREAD (0x0002)
#define PROCESS_SUSPEND_RESUME (0x0800)
#define PROCESS_VM_OPERATION (0x0008)
#define PROCESS_VM_WRITE (0x0020)

// structures for the callbacks we need to initialize
typedef struct _ImageLoadCallback {
    PLOAD_IMAGE_NOTIFY_ROUTINE ImageLoadCallbackPtr;
    BOOLEAN IsRegistered;
} ImageLoadCallback, * PImageLoadCallback;

typedef struct _ProcessLoadCallback {
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX CreateProcessNotifyPtr;
    BOOLEAN IsRegistered;
} ProcessLoadCallback, * PProcessLoadCallback;

// @reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration
typedef struct _OpenProcessCallback {
    POB_PRE_OPERATION_CALLBACK OpenProcessNotifyPtr;
    PVOID RegistrationHandle;
    BOOLEAN IsRegistered;
} OpenProcessCallback, *POpenProcessCallback;

typedef struct _CallbackState {
    ImageLoadCallback ImageLoadNotify;
    ProcessLoadCallback ProcessNotify;
    OpenProcessCallback OpenProcessNotify;
} CallbackState, *PCallbackState;

typedef struct _ProtectedProcessEntry {
    PUNICODE_STRING Name;
    HANDLE ProcessId;
    LIST_ENTRY CurrentEntry;
} ProtectedProcessEntry, *PProtectedProcessEntry;

typedef struct _ActiveProtectedProcessEntry {
    PUNICODE_STRING Name;
    HANDLE ProcessId;
    LIST_ENTRY CurrentEntry;
} ActiveProtectedProcessEntry, *PActiveProtectedProcessEntry;

typedef struct _BlisterState {
    // guarded mutex to "lock" the structure down to avoid
    // having threads and functions concurrently accessing the structure's attributes
    KGUARDED_MUTEX InUse;
    // an array of 10 handles, this is used to get the PID and then HANDLE
    // to the process / processes that need to be set as PPL
    // this variable is a "cache" because it contains the first 10 entries of
    // the ActiveSelfProtectedProcesses list to avoid having to
    // enumerate the linked list everytime,
    HANDLE CacheSelfProtectedPIDs[10];
    // list of all the processes we need to set as protected
    // this can either contain the PID of the process or the process name
    LIST_ENTRY SelfProtectedProcesses;
    // list of active PPLs
    LIST_ENTRY ActiveSelfProtectedProcesses;
    // list of callbacks
    CallbackState Callbacks;
} BlisterState, * PBlisterState;