# loading-techs
A collection of various PoCs of loading and running code

Originaly, I wanted to store only Sharp examples, but when I realised that It'll be useful to have C++ examples as well.

## Sharp

### Done
1. DLL Injectors
    - Classic (?)
2. Shellcode Injectors
    - Classic
    - Thread Hijacking (If there is only main thread, the target program will not respond)
    - Native API quadro (Inter-Process Mapped View)
    - Process Hollowing
3. Shellcode Runners
    - Classic
    - Local Thread Hijacking (If Binary was built as Debug, it'll not work. But in other cases, it works perfectly)
    - CreateThreadpoolWait
4. Sharp Runners
    - Reflection-Runner (Assembly.Load)
    - Sharp-Runner (with Delegate)

### TODO
1. Dll Injectors
    - Reflective DLL Injection
    - Shellcode Reflective DLL Injection
    - Module Stomping
2. Sharp Runners
    - Custom Garbage Collector
3. Shellcode Injectors
    - Process Doppelganging
    - Process Ghosting
    - Process Herpaderping
    - Dirty Vanity
    - Native API quadro
    - Remote Thread Hijacking
    - Asychronous Procedure Call Injection
    - Atom Bombing
    - SetWindowsHook
4. Shellcode Runners
    - Run code from .text section without Win API
    - Inline Execution in C/C++
    - Avoiding RWX memory sections with AddressOfEntryPoint
    - Inject .NET binary from unmanaged process (CLR Hosting API)
    - Thread Stack Spoofing / Call Stack Spoofing

## C++

### Done
1. Dll Injectors
    - Classic
2. Shellcode Injectors
    - Classic
    - Process Hollowing (unfinished)
3. Shellcode Runners
    - Classic
    - Local Thread Hijacking (empty)

### TODO
1. Dll Injectors
    - Reflective DLL Injection
    - Shellcode Reflective DLL Injection
    - Module Stomping
2. Sharp Runners
    - Custom Garbage Collector
3. Shellcode Injectors
    - Process Hollowing
    - Process Doppelganging
    - Process Ghosting
    - Process Herpaderping
    - Dirty Vanity
    - Native API quadro
    - Remote Thread Hijacking
    - Asychronous Procedure Call Injection
    - Atom Bombing
    - SetWindowsHook
4. Shellcode Runners
    - Local Thread Hijacking
    - CreateThreadpoolWait
    - Run code from .text section without Win API
    - Inline Execution in C/C++
    - Avoiding RWX memory sections with AddressOfEntryPoint
    - Inject .NET binary from unmanaged process (CLR Hosting API)
    - Thread Stack Spoofing / Call Stack Spoofing