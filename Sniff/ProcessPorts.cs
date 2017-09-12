using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace MJSniff
{
    public enum TCP_TABLE_CLASS
    {
        //TCP_TABLE_BASIC_LISTENER = 0,
        //TCP_TABLE_BASIC_CONNECTIONS = 1,
        //TCP_TABLE_BASIC_ALL = 2,
        TCP_TABLE_OWNER_PID_LISTENER = 3,
        TCP_TABLE_OWNER_PID_CONNECTIONS = 4,
        TCP_TABLE_OWNER_PID_ALL = 5
        //TCP_TABLE_OWNER_MODULE_LISTENER = 6,
        //TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7,
        //TCP_TABLE_OWNER_MODULE_ALL = 8
    }
    public enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC = 0,
        UDP_TABLE_OWNER_PID = 1
        //UDP_TABLE_OWNER_MODULE = 2
    }

    public struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    public class iphlpapi
    {
        static uint AF_INET = 2; //2:IPv4

        [DllImport("iphlpapi.dll", SetLastError = true, CharSet = CharSet.Auto, ExactSpelling = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, uint ulAf, TCP_TABLE_CLASS TableClass, int Reserved);

        [DllImport("iphlpapi.dll", SetLastError = true, CharSet = CharSet.Auto, ExactSpelling = true)]
        static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, uint ulAf, UDP_TABLE_CLASS TableClass, int Reserved);

        private static uint swapuint(uint val)
        {
            uint ans = (0x0000FF00 & val) >> 8 | (0x000000FF & val) << 8;
            return ans;
        }

        public static int getTcpOwnerPid(int port)
        {
            IntPtr buffTable = IntPtr.Zero;
            int buffSize = 0;
            try
            {
                GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
                buffTable = Marshal.AllocHGlobal(buffSize);
                GetExtendedTcpTable(buffTable, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
            }
            catch (Exception)
            {
                if (IntPtr.Zero != buffTable)
                {
                    Marshal.FreeHGlobal(buffTable);
                }
                return 0;
            }
            int usz = Marshal.SizeOf(typeof(uint));
            IntPtr wkPtr = buffTable;                   
            int dwNumEntries = Marshal.ReadInt32(wkPtr);
            wkPtr = IntPtr.Add(wkPtr, usz);
            for (int i = 0; i < dwNumEntries; i++)
            {
                MIB_TCPROW_OWNER_PID mtop = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(wkPtr, typeof(MIB_TCPROW_OWNER_PID));
                if (swapuint(mtop.dwLocalPort) == port)
                    return int.Parse(mtop.dwOwningPid.ToString());
                wkPtr = IntPtr.Add(wkPtr, Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
            }
            if (IntPtr.Zero != buffTable)
            {
                Marshal.FreeHGlobal(buffTable);
            }
            return 0;
        }

        public static int getUdpOwnerPid(int port)
        {
            IntPtr buffTable = IntPtr.Zero;
            int buffSize = 0;
            try
            {
                GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                buffTable = Marshal.AllocHGlobal(buffSize);
                GetExtendedUdpTable(buffTable, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            }
            catch (Exception)
            {
                if (IntPtr.Zero != buffTable)
                {
                    Marshal.FreeHGlobal(buffTable);
                }
                return 0;
            }
            int usz = Marshal.SizeOf(typeof(uint));
            IntPtr wkPtr = buffTable;
            int dwNumEntries = Marshal.ReadInt32(wkPtr);
            wkPtr = IntPtr.Add(wkPtr, usz);
            for (int i = 0; i < dwNumEntries; i++)
            {

                MIB_UDPROW_OWNER_PID mtop = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(wkPtr, typeof(MIB_UDPROW_OWNER_PID));
                if (swapuint(mtop.dwLocalPort) == port)
                    return int.Parse(mtop.dwOwningPid.ToString());
                wkPtr = IntPtr.Add(wkPtr, Marshal.SizeOf(typeof(MIB_UDPROW_OWNER_PID)));
            }
            if (IntPtr.Zero != buffTable)
            {
                Marshal.FreeHGlobal(buffTable);
            }
            return 0;
        }

        public static int FindPIDFromPort(int port, bool isUdp = false)
        {
            int pid = 0;
            if (isUdp)
            {
                pid = getUdpOwnerPid(port);
            }
            else
            {
                pid = getTcpOwnerPid(port);
            }
            return pid;
        }
    }
}