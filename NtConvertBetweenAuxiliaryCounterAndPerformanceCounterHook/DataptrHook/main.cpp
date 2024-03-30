#include <Windows.h>
#include <iostream>

PVOID(NTAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(ULONG64, PVOID, PVOID, PVOID);
typedef struct _HOOK_DATA
{
	DWORD Magic;
	int ControlCode;
}HOOK_DATA, * PHOOK_DATA;


int main()
{
	std::cout << "[*] resolving NtConvertBetweenAuxiliaryCounterAndPerformanceCounter from ntdll.dll" << std::endl;
	*(PVOID*)&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)
	{
		std::cerr << "[*} failed to resolve NtConvertBetweenAuxiliaryCounterAndPerformanceCounter" << std::endl;
		return -1;
	}
	std::cout << "[*] resolved NtConvertBetweenAuxiliaryCounterAndPerformanceCounter" << std::endl;

	std::cout << "[*} sending command to driver" << std::endl;
	HOOK_DATA Data;
	Data.Magic = 0x77FF77FF;
	Data.ControlCode = 7;
	PVOID pData = (PVOID)&Data;
	INT64 Status = 0;

	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(1, &pData, &Status, 0);




	return 0; 
}