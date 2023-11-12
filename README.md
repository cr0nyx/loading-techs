# loading-techs

A collection of various PoCs of loading and running code

Originaly, I wanted to store only Sharp examples, but when I realised that It'll be useful to have C++ examples as well.

Runner - runs shellcode in local process
Injector - runs shellcode in remote process

## Sharp

### Done
1. DLL Injectors
    - Classic (?)
    - Module Stomping
2. Shellcode Injectors
    - Classic
    - Thread Hijacking (If there is only main thread, the target program will not respond)
    - Native API quadro (Inter-Process Mapped View)
    - APC (not any process calls APC, notepad for example)
    - Early Bird
    - IAT Hooking
3. Shellcode Runners
    - Classic
    - Thread Hijacking (If Binary was built as Debug, it'll not work. But in other cases, it works perfectly)
    - CreateThreadpoolWait
    - APC
    - Fibers
4. Sharp Runners
    - Reflection-Runner (Assembly.Load)
    - Sharp-Runner (with Delegate)

### TODO
1. Dll Injectors
    - Reflective DLL Injection
    - Shellcode Reflective DLL Injection
2. Shellcode Runners
    - IAT Hooking
5. Sharp Runners
    - Roslyn 

## C++

### Done
1. Dll Injectors
    - Classic
    - Module Stomping (works weird: works even if process was closed (not terminated), but if its stager - it wont load additional part (because dll has fixed size in memory))
    - Reflective DLL Injection (error)
2. Shellcode Injectors
    - Classic
    - Remote Thread Hijacking
    - APC
    - Native API quadro
    - SetWindowsHookEx
    - Early Bird
3. Shellcode Runners
    - Classic
    - APC
    - Fibers
    - CreateThreadpoolWait
    - IAT Hooking

### TODO
1. Dll Injectors
    - Shellcode Reflective DLL Injection
2. Shellcode Runners
    - Local Thread Hijacking (empty right now)
3. Shellcode Injectors
    - IAT Hooking