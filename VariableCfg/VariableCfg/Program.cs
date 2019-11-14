using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using UINT8 = System.Byte;
using UINT16 = System.UInt16;
using UINT32 = System.UInt32;

namespace VariableCfg
{
    public class Global
    {
        public static List<byte> DataList = new List<byte>();
    }
    class Program
    {
        [DllImport("kernel32.dll", EntryPoint = "SetProcessWorkingSetSize", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool SetProcessWorkingSetSize(IntPtr pProcess, int dwMinimumWirkingSetSize, int dwMaximumWorkingSetSize);
        [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcess", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr GetCurrentProcess();
        //
        [DllImport("kernel32.dll")]
        private extern static IntPtr LoadLibrary(String DllName);

        [DllImport("kernel32.dll")]
        private extern static IntPtr GetProcAddress(IntPtr hModule, String ProcName);

        [DllImport("kernel32")]
        private extern static bool FreeLibrary(IntPtr hModule);

        //  setvariable
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        //[DllImport("kernel32.dll", ExactSpelling = true)] // 6/8
        //internal static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
        phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name,
        ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        internal const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege"; //http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx

        [DllImport("kernel32.dll", EntryPoint = "SetFirmwareEnvironmentVariable", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetFirmwareEnvironmentVariable([MarshalAs(UnmanagedType.LPTStr)] string lpName, [MarshalAs(UnmanagedType.LPTStr)] string lpGuid, ref UINT8[] pBuffer, int nSize);

        [DllImport("kernel32.dll", EntryPoint = "SetFirmwareEnvironmentVariableEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static unsafe extern bool SetFirmwareEnvironmentVariableEx(string lpName, string lpGuid, IntPtr pValue, int nSize, int Attributes);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 GetFirmwareEnvironmentVariable(string lpName, string lpGuid, UINT8[] pBuffer, int nSize);
        static bool SetPriv()
        {
            try
            {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, SE_SYSTEM_ENVIRONMENT_NAME, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
            }
            catch (Exception ex)
            {
                throw;
                // return false;
            }
        }
        ///////end setvariable
        public static void SetVariable(string GUID, string NAME, int ATTRIBUTES, List<byte> DataList)
        {
            byte[] Data = new byte[DataList.Count];
            int i = 0;
            foreach (byte by in DataList)
            {
                Data[i] = by;
                i++;
            }
            IntPtr unmanagedPointer = IntPtr.Zero;
            unmanagedPointer = Marshal.AllocHGlobal(Data.Length);
            Marshal.Copy(Data, 0, unmanagedPointer, Data.Length);

            var ResultsANSII = SetFirmwareEnvironmentVariableEx(NAME, GUID, unmanagedPointer, sizeof(byte) * Data.Length, ATTRIBUTES);
            if (ResultsANSII)
                Console.WriteLine("Set variable success!");
            else
            {
                Console.WriteLine(" Set variable fail!\n Check your GUID format(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)\n or check the variable name");
                var error = Marshal.GetLastWin32Error();
                Console.WriteLine("error code:" + error);
            }
            Marshal.FreeHGlobal(unmanagedPointer);
        }

        public static void SetVariable2(string NAME, string GUID, List<byte> DataList)
        {
            byte[] Data = new byte[DataList.Count];
            int i = 0;
            foreach (byte by in DataList)
            {
                Data[i] = by;
                i++;
            }
            //IntPtr unmanagedPointer = IntPtr.Zero;
            //unmanagedPointer = Marshal.AllocHGlobal(Data.Length);
            //Marshal.Copy(Data, 0, unmanagedPointer, Data.Length);

            var ResultsANSII = SetFirmwareEnvironmentVariable(NAME, GUID,ref Data, sizeof(byte) * Data.Length);
            if (ResultsANSII)
                Console.WriteLine("Set variable success!");
            else
            {
                Console.WriteLine(" Set variable fail!");
                var error = Marshal.GetLastWin32Error();
                Console.WriteLine("error code:"+error);
            }
            //Marshal.FreeHGlobal(unmanagedPointer);
        }
        public static void GetVariable(string GUID, string NAME,int size)
        {
            byte[] Data = new byte[size];
            //IntPtr unmanagedPointer = Marshal.AllocHGlobal(Data.Length);
            var Results = GetFirmwareEnvironmentVariable(NAME, GUID, Data, sizeof(byte) * Data.Length);
            if (Results!=0)
            {
                Console.WriteLine("Get variable success!");
                foreach (var item in Data)
                {
                    Console.Write(item.ToString("x").PadLeft(2,'0')+" ");
                }
            }

            else
                Console.WriteLine(" Get variable fail!\n Check your GUID format(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)\n or add the size parameter to get more buffer");
            var error = Marshal.GetLastWin32Error();
        }

        public static void DelVariable(string GUID, string NAME)
        {
            byte[] Data = new byte[4];
            IntPtr unmanagedPointer = IntPtr.Zero;
            unmanagedPointer = Marshal.AllocHGlobal(Data.Length);
            Marshal.Copy(Data, 0, unmanagedPointer, Data.Length);

            var ResultsANSII = SetFirmwareEnvironmentVariableEx(NAME, GUID, unmanagedPointer, 0, 0x0000007);
            if (ResultsANSII)
                Console.WriteLine("Delete variable success!");
            else
            {
                Console.WriteLine("Delete variable fail!");
                var error = Marshal.GetLastWin32Error();
                Console.WriteLine("error code:" + error);
            }
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        static unsafe void Main(string[] args)
        {
            bool retVal;
            retVal = SetPriv();

            if (args.Length == 0)
            {
                Console.WriteLine("-----VariableCfg by Jason Lin-----");
                Console.WriteLine("Get variable: VariableCfg.exe /g VariableName GUID size:default 4 bytes");
                Console.WriteLine("Set variable: VariableCfg.exe /s VariableName GUID");
                Console.WriteLine("Delete variable: VariableCfg.exe /d VariableName GUID");
                Console.WriteLine("-----------------------------------");
                Console.WriteLine("See Example: VariableCfg.exe /e");
                Console.WriteLine("-----------------------------------");
                Console.WriteLine("Any bugs or suggestion? Contact me: advance07144@gmail.com");


                return;
            }
            switch (args[0])
            {
                default:
                case null:
                case "/?":
                case "?":
                case "help":
                case "HELP":
                case "h":
                case "H":
                    Console.WriteLine("-----VariableCfg by Jason Lin-----");
                    Console.WriteLine("Get variable: VariableCfg.exe /g VariableName GUID size:default 4 bytes");
                    Console.WriteLine("Set variable: VariableCfg.exe /s VariableName GUID");
                    Console.WriteLine("Delete variable: VariableCfg.exe /d VariableName GUID");
                    Console.WriteLine("-----------------------------------");
                    Console.WriteLine("See Example: VariableCfg.exe /e");
                    Console.WriteLine("-----------------------------------");
                    Console.WriteLine("Any bugs or suggestion? Contact me: advance07144@gmail.com");
                    Console.WriteLine("Icon made by Smashicons from www.flaticon.com");
                    break;
                case "/g":
                case "/G":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Get variable: VariableCfg.exe /g VariableName GUID");
                    }
                    else if(args.Length == 3)
                    {
                        args[2] = "{" + args[2] + "}";
                        GetVariable(args[2], args[1],4);
                    }
                    else if(args.Length == 4)
                    {
                        args[2] = "{" + args[2] + "}";
                        GetVariable(args[2], args[1], Convert.ToInt32(args[3])); ;
                    }
                    break;
                case "/s":
                case "/S":
                    if (args.Length < 4)
                    {
                        Console.WriteLine("Set variable: VariableCfg.exe /s VariableName GUID Data");
                    }
                    else
                    {
                        //byte[] StringToByte = Encoding.ASCII.GetBytes(args[3]);
                        byte[] StringToByte = StringToByteArray(args[3]);
                        Global.DataList.Clear();
                        //Global.DataList.Capacity = StringToByte.Length;
                        foreach (byte eachByte in StringToByte)
                        {
                            Global.DataList.Add(eachByte);
                        }
                        args[2] = "{" + args[2] + "}";
                        SetVariable(args[2], args[1], 0x0000007, Global.DataList);
                        //SetVariable2(args[1], args[2], Global.DataList);
                    }
                    break;
                case "/d":
                case "/D":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Delete variable: VariableCfg.exe /d VariableName GUID");
                    }
                    else
                    {
                        args[2] = "{" + args[2] + "}";
                        DelVariable(args[2], args[1]);
                    }
                    break;
                case "/e":
                case "/E":
                    Console.WriteLine("-----Get variable Example-----");
                    Console.WriteLine("Get variable");
                    Console.WriteLine("VariableCfg.exe /g VariableName GUID size(default 4 bytes)");
                    Console.WriteLine("VariableCfg.exe /g VariTest 12345678-1234-1234-1234-123456781234 10");
                    Console.WriteLine("VariableCfg.exe /g VariTest2 12345678-1234-1234-1234-123456781235");
                    Console.WriteLine("-----Set variable Example-----");
                    Console.WriteLine("Set variable");
                    Console.WriteLine("VariableCfg.exe /s VariableName GUID Data");
                    Console.WriteLine("VariableCfg.exe /s VariTest 12345678-1234-1234-1234-123456781234 1f7c6300");
                    Console.WriteLine("-----Delete variable Example-----");
                    Console.WriteLine("Delete variable:");
                    Console.WriteLine("VariableCfg.exe /d BootOrder 8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
                    break;

            }
        }
    }
}
