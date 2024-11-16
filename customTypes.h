#pragma once

#include <ntddk.h>

// process-specific access masks
// @reference https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
#define PROCESS_TERMINATE (0x0001)
#define PROCESS_CREATE_THREAD (0x0002)
#define PROCESS_SUSPEND_RESUME (0x0800)
#define PROCESS_VM_WRITE (0x0020)
#define PROCESS_VM_OPERATION (0x0008)

#define uint8_t unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long long
#define int8_t char
#define int16_t short
#define int32_t int
#define int64_t long long

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
}OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

// @reference https://github.com/hfiref0x/Misc/blob/master/source/DSEPatch/DSEPatch/ntdll/ntos.h#L4136
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

// @reference https://www.vergiliusproject.com/kernels/x64/windows-10/21h2/_OBJECT_TYPE
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

// structures for the callbacks we need to initialize
typedef struct _ImageLoadCallback {
    PLOAD_IMAGE_NOTIFY_ROUTINE ImageLoadCallbackPtr;
    BOOLEAN IsRegistered;
} ImageLoadCallback, *PImageLoadCallback;

typedef struct _ProcessLoadCallback {
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX CreateProcessNotifyPtr;
    BOOLEAN IsRegistered;
} ProcessLoadCallback, *PProcessLoadCallback;

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
    LIST_ENTRY CurEntry;
} ProtectedProcessEntry, *PProtectedProcessEntry;

typedef struct _ActiveProtectedProcessEntry {
    PUNICODE_STRING Name;
    HANDLE ProcessId;
    LIST_ENTRY CurEntry;
} ActiveProtectedProcessEntry, *PActiveProtectedProcessEntry;

typedef struct _BlisterState {
    // an array of 10 handles, this is used to get the PID and then HANDLE
    // to the process / processes that need to be set as PPL
    // this variable is a "cache" because it contains the first 10 entries of
    // the ActiveSelfProtectedProcesses list to avoid having to
    // enumerate the linked list everytime
    HANDLE CacheSelfProtectedPIDs[10];
    // guarded mutex to "lock" the structure down to avoid
    // having threads and functions concurrently accessing the structure's attributes
    KGUARDED_MUTEX Lock;
    // list of callbacks
    CallbackState Callbacks;
    // list of all the processes we need to set as protected
    // this can either contain the PID of the process or the process name
    LIST_ENTRY SelfProtectedProcesses;
    // list of active PPLs
    LIST_ENTRY ActiveSelfProtectedProcesses;
} BlisterState, *PBlisterState;