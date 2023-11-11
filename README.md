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
    - APC (not any process calls APC, notepad for example)
    - Atom Bombing (I'm not sure that it works properly)
3. Shellcode Runners
    - Classic
    - Thread Hijacking (If Binary was built as Debug, it'll not work. But in other cases, it works perfectly)
    - CreateThreadpoolWait
    - Fibers
    - APC
4. Sharp Runners
    - Reflection-Runner (Assembly.Load)
    - Sharp-Runner (with Delegate)
5. PE Runners
    - Process Hollowing
    - Process Doppelganging (have code, but it's not working:( )

### TODO
1. Dll Injectors
    - Reflective DLL Injection
    - Shellcode Reflective DLL Injection
    - Module Stomping
2. Advanced Runners
    - Thread Stack Spoofing / Call Stack Spoofing
    - Avoiding RWX memory sections with AddressOfEntryPoint
3. PE Runners
    - Process Ghosting
    - Process Herpaderping
    - Dirty Vanity
4. Sharp Runners
    - SyntaxTree 

## C++

### Done
1. Dll Injectors
    - Classic
2. Shellcode Injectors
    - Classic
    - Remote Thread Hijacking
    - APC
    - Native API quadro
    - SetWindowsHookEx
    - Early Bird
3. Shellcode Runners
    - Classic
    - Local Thread Hijacking (empty)
    - APC
    - Fibers
    - CreateThreadpoolWait
    - IAT Hooking
4. PE-Runners
    - Process Hollowing (unfinished)

### TODO
1. Dll Injectors
    - Reflective DLL Injection
    - Shellcode Reflective DLL Injection
    - Module Stomping
2. Advanced Runners
    - Thread Stack Spoofing / Call Stack Spoofing
    - Atom Bombing
3. Shellcode Injectors
    - IAT Hooking
    - Avoiding RWX memory sections with AddressOfEntryPoint
3. PE-Runners
    - Process Hollowing
    - Process Doppelganging
    - Process Ghosting
    - Process Herpaderping
    - Dirty Vanity
4. C-Runners
    - Run code from .text section without Win API
    - Inline Execution in C/C++
    - Inject .NET binary from unmanaged process (CLR Hosting API)
    - Custom Garbage Collector