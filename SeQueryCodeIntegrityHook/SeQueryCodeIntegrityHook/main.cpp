#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>

#define Log(content) std::wcout << content
#pragma comment(lib,"ntdll.lib")

typedef struct _HOOK_STRUCT_CODE_INTEGRITY_INFO {
	ULONG   Length;
	UINT16   Magic;
	UINT16 ControlCode;

} HOOK_STRUCT_CODE_INTEGRITY_INFO, * PHOOK_STRUCT_CODE_INTEGRITY_INFO;
int main()
{

	void* LastBuffer = nullptr;
	void* InfoBuffer = nullptr;
	ULONG ReturnLength;
	HOOK_STRUCT_CODE_INTEGRITY_INFO CodeIntegrityInfo;
	CodeIntegrityInfo.Length = 8;
	CodeIntegrityInfo.Magic = 0x7775;
	CodeIntegrityInfo.ControlCode = 0x1212;

	NTSTATUS status = NtQuerySystemInformation(SystemCodeIntegrityInformation, &CodeIntegrityInfo, sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), &ReturnLength);
	if (!NT_SUCCESS(status))
	{
		Log(L"[-] NtQuerySystemInformation failed with status 0x" << std::hex << status << std::endl);
		return -1;
	}

	Log(L"[-] successfully made a query for code integrity information" << std::endl);
	
	return 0;
}