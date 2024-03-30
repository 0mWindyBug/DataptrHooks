#include "defs.h"
#include <ntddk.h>

#define DATA_PTR_OFFSET 0x0000000000c1d958

PVOID g_OriginalAddress = NULL;
PVOID* g_DataPtr = NULL;

typedef INT64(*CiCodeIntegrityPtr)(INT64 InfoBuffer, INT64 InfoLength, INT64 Size, INT64 v);

typedef struct _HOOK_STRUCT_CODE_INTEGRITY_INFO {
    ULONG   Length;
    UINT16   Magic;
    UINT16   ControlCode;

} HOOK_STRUCT_CODE_INTEGRITY_INFO, * PHOOK_STRUCT_CODE_INTEGRITY_INFO;


PCHAR GetNameFromFullName(PCHAR FullName) {
    SIZE_T FullNameLength = strlen(FullName);

    for (SIZE_T i = FullNameLength; i > 0; i--) {
        if (*(FullName + i) == '\\') {
            return FullName + i + 1;
        }
    }

    return NULL;
}

PVOID GetNtoskrnlBase()
{

    PVOID LocalIntBase = NULL;
    PRTL_PROCESS_MODULES ModuleInformation = NULL;
    NTSTATUS result;
    ULONG SizeNeeded;
    SIZE_T InfoRegionSize;
    BOOL output = FALSE;
    PROTOTYPE_ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
    UNICODE_STRING ZQSIname;
    // Get addr of zqsi
    RtlInitUnicodeString(&ZQSIname, L"ZwQuerySystemInformation");
    ZwQuerySystemInformation = (PROTOTYPE_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&ZQSIname);
    // Get info size 
    result = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, NULL, 0, &SizeNeeded);
    if (result != 0xC0000004)
    {
        return NULL;
    }
    InfoRegionSize = SizeNeeded;
    // Get Info 
    while (result == 0xC0000004)
    {
        InfoRegionSize += 0x1000;
        ModuleInformation = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPoolNx, InfoRegionSize);
        if (ModuleInformation == NULL)
        {
            return NULL;
        }
        result = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, (PVOID)ModuleInformation, (ULONG)InfoRegionSize, &SizeNeeded);
        if (!NT_SUCCESS(result))
        {
            return NULL;
        }
        // Enumerate through loaded drivers
        for (DWORD i = 0; i < ModuleInformation->NumberOfModules; i++)
        {
            if (!strcmp(GetNameFromFullName((PCHAR)ModuleInformation->Modules[i].FullPathName), "ntoskrnl.exe"))
            {
                PVOID base = ModuleInformation->Modules[i].ImageBase;
                ExFreePool(ModuleInformation);
                return base;

            }
        }

    }
    ExFreePool(ModuleInformation);
    return NULL;
}



INT64 Hook(PVOID InfoBuffer, INT64 InfoLength, INT64 Size, INT64 v)
{
    DbgPrint("[*] CiQueryInformation was called!\n");
    CiCodeIntegrityPtr OriginalFunction = (CiCodeIntegrityPtr)g_OriginalAddress;
    if (!ExGetPreviousMode() == UserMode)
    {
        DbgPrint("[*] kernel mode request , retruning...\n");
        return OriginalFunction(InfoBuffer, InfoLength, Size,v);
    }

    PHOOK_STRUCT_CODE_INTEGRITY_INFO UserData = (PHOOK_STRUCT_CODE_INTEGRITY_INFO)InfoBuffer;
    if (UserData->Magic == 0x7775)
    {
        DbgPrint("[*] Received control number %d from client!\n", UserData->ControlCode);
        return NULL;
    }
    else
    {
        DbgPrint("[*] magic didnt match , calling original function...\n");
        return OriginalFunction(InfoBuffer, InfoLength, Size,v);
    }
}


BOOLEAN PlaceHook()
{
    PVOID KernelBase = GetNtoskrnlBase();
    if (!KernelBase)
        return FALSE;
    DbgPrint("[*] ntoskrnl.exe at 0x%p\n", KernelBase);


    g_DataPtr = (PVOID*)((ULONG_PTR)KernelBase + DATA_PTR_OFFSET);
    if (!MmIsAddressValid(g_DataPtr))
        return FALSE;

    g_OriginalAddress = *g_DataPtr;

    DbgPrint("[*] placing hook on 0x%p ( original function at 0x%p , hook at 0x%p)\n", g_DataPtr, g_OriginalAddress, Hook);

    InterlockedExchange64((volatile LONG64*)g_DataPtr, (LONG64)Hook);

    return TRUE;

}

void RemoveHook()
{
    InterlockedExchange64((volatile LONG64*)g_DataPtr, (LONG64)g_OriginalAddress);
}



void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    RemoveHook();
    DbgPrint("[*] driver unloaded\n");
}



EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[*] driver loading\n");

    if (!PlaceHook())
    {
        DbgPrint("[*] failed to place hook on data ptr\n");
    }



    DbgPrint("[*] successfully placed data ptr hook!\n");



    return status;
}