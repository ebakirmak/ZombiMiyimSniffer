using System;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Net.Sockets;
using System.Net;
using MJSniff;
using System.Diagnostics;
using System.Management;
using System.Text;
using System.Threading;
using System.Collections;
using System.Linq;
using System.Reflection;
using System.IO;

namespace Sniffer
{
    public enum Protocol
    {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };
    public partial class snifferForm : Form
    {

        public snifferForm()
        {
            CheckForIllegalCrossThreadCalls = false;
            InitializeComponent();
        }

        
        public class Packet
        {
            public DateTime TimeStamp;

            public string destIp;
            public int destPort;

            public int procPid;
           /* public string procName;
            public string procOwner;*/

            public string Type;
            public int lenght;
            //public byte[] packet;
        }
        public class Packetx
        {
            public DateTime TimeStamp;
            public string destIp;
            public int destPort;

            public int procPid;
           /* public string procName;
            public string procOwner;*/

            public string Type;
            public int Averagelenght;
            public int count;
        }
        Dictionary<long, Packet> packets = new Dictionary<long, Packet> { };
        Dictionary<long, Packetx> possibleDDos = new Dictionary<long, Packetx> { };
        uint packetID = 0;
        uint DDosID = 0;

        private Socket mainSocket;                          //The socket which captures all incoming packets
        private byte[] byteData = new byte[65556];
        private bool bContinueCapturing = false;            //A flag to check if packets are to be captured or not
        private delegate void AddTreeNode(TreeNode node);

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (cmbInterfaces.Text == "")
            {
                MessageBox.Show("Select an Interface to capture the packets.", "Sniffer", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            try
            {
                if (!bContinueCapturing)        
                {
                    //Start capturing the packets...

                    btnStart.Text = "&Stop";

                    bContinueCapturing = true;

                    //For sniffing the socket to capture the packets has to be a raw socket, with the
                    //address family being of type internetwork, and protocol being IP
                    mainSocket = new Socket(AddressFamily.InterNetwork,
                        SocketType.Raw, ProtocolType.IP);
                    mainSocket.ReceiveBufferSize = 65556 ;
                    //Bind the socket to the selected IP address
                    mainSocket.Bind(new IPEndPoint(IPAddress.Parse(cmbInterfaces.Text), 0));

                    //Set the socket  options
                    mainSocket.SetSocketOption(SocketOptionLevel.IP,            //Applies only to IP packets
                                               SocketOptionName.HeaderIncluded, //Set the include the header
                                               true);                           //option to true

                    byte[] byTrue = new byte[4] {1, 0, 0, 0};
                    byte[] byOut = new byte[4]{1, 0, 0, 0}; //Capture outgoing packets

                    //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                    mainSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                                                                //of Winsock 2
                                         byTrue,                                    
                                         byOut);

                    //Start receiving the packets asynchronously
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                        new AsyncCallback(OnReceive), null);
                }
                else
                {
                    btnStart.Text = "&Start";
                    bContinueCapturing = false;
                    //To stop capturing the packets close the socket
                    mainSocket.Close ();
                }
            }
            catch (Exception ex)
            {
               // MessageBox.Show(ex.Message, "Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mainSocket.EndReceive(ar);
               /* ThreadStart start = () =>
                {*/
                    ParseData(byteData, nReceived, packets);
               /* };
                Thread t = new Thread(start);*/
                //t.Start();
                if (bContinueCapturing)     
                {
                    byteData = new byte[65556];
                    //Another call to BeginReceive so that we continue to receive the incoming packets
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,new AsyncCallback(OnReceive), null);
                }
            }
            catch
            {
                if (bContinueCapturing)
                {
                    byteData = new byte[65556];
                    //Another call to BeginReceive so that we continue to receive the incoming packets
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
                }
            }
                
        }

        private void ParseData(byte[] byteData, int nReceived, Dictionary<long, Packet> packets)
        {
           
                Packet newOne = new Packet();
                IPHeader ipHeader = new IPHeader(byteData, nReceived);

                switch (ipHeader.ProtocolType)
                {
                    case Protocol.TCP:
                        TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);
                        newOne.TimeStamp = DateTime.Now;
                        newOne.destIp = ipHeader.DestinationAddress.ToString();
                        newOne.destPort = int.Parse(tcpHeader.DestinationPort);
                        newOne.lenght = tcpHeader.MessageLength;
                        //newOne.packet = tcpHeader.Data;
                        newOne.procPid = iphlpapi.FindPIDFromPort(int.Parse(tcpHeader.SourcePort));
                       /* newOne.procName = Process.GetProcessById(newOne.procPid).ProcessName;
                        newOne.procOwner = GetProcessOwner(newOne.procPid);*/
                        newOne.Type = "TCP"; tcpHeader.clear();
                        break;

                    case Protocol.UDP:
                        UDPHeader udpHeader = new UDPHeader(ipHeader.Data, (int)ipHeader.MessageLength);
                        newOne.TimeStamp = DateTime.Now;
                        newOne.destIp = ipHeader.DestinationAddress.ToString();
                        newOne.destPort = int.Parse(udpHeader.DestinationPort);
                        newOne.lenght = int.Parse(udpHeader.Length);
                        //newOne.packet = udpHeader.Data;
                        newOne.procPid = iphlpapi.FindPIDFromPort(int.Parse(udpHeader.SourcePort));
                       /* newOne.procName = Process.GetProcessById(newOne.procPid).ProcessName;
                        newOne.procOwner = GetProcessOwner(newOne.procPid);*/
                        newOne.Type = "UDP";
                        udpHeader.clear();
                        break;
                    case Protocol.Unknown:
                        return;
                }

                if (newOne.lenght < 20/* || newOne.procOwner == "SYSTEM"*/)
                    return;

                /*if (Encoding.UTF8.GetString(newOne.packet).ToLower().IndexOf("http") != -1 || Encoding.UTF8.GetString(newOne.packet).ToLower().IndexOf("none") != -1)
                    newOne.Type = "HTTP";
             */
                
                packetID++;
                packets.Add(packetID, newOne);
                checkDos(newOne);
                addNode(newOne);
                ipHeader.clear();
            
        }

        public void addNode(Packet a)
        {
           /*TreeNode rootNode = new TreeNode();
            AddTreeNode addTreeNode = new AddTreeNode(OnAddTreeNode);

            rootNode.Text = a.TimeStamp + " |" +
                a.Type + " |" +
                a.destIp + ":" + a.destPort + " |" +
                /*a.procOwner + "/" + a.procName + " |" +
                a.lenght + " |";
            if (a.Type == "HTTP")
            {
                rootNode.BackColor = System.Drawing.Color.Cyan;
               // rootNode.Text += Encoding.UTF8.GetString(a.packet);
            }
            else
            {
                if (a.Type == "TCP")
                    rootNode.BackColor = System.Drawing.Color.SpringGreen;
                else
                    rootNode.BackColor = System.Drawing.Color.Orange;
               // rootNode.Text += Convert.ToBase64String(a.packet).Replace('A',' ');
            }
            
            //Thread safe adding of the nodes
            treeView.Invoke(addTreeNode, new object[] { rootNode });*/
        }
        private delegate void addDosList();
        public void addDosListx()
        {
            atkList.Items.Clear();
            foreach (Packetx s in possibleDDos.Values.ToList())
                atkList.Items.Add(String.Format("{5}|{0}|{1}:{2}|{3}|{4}", Process.GetProcessById(s.procPid).ProcessName, s.destIp, s.destPort, s.count, s.Averagelenght,s.Type));
        }
        public void checkDos(Packet newOne)
        {
            /*if (System.Runtime.InteropServices.Marshal.SizeOf(packets.ToList()) > 400084)
                packets = new Dictionary<ulong, Packet> { };*/
             packets = packets.ToList().Where(p => DateTime.Now.Subtract(p.Value.TimeStamp).TotalSeconds < 20)
                    .ToDictionary(p => p.Key, p => p.Value);  // 60 saniyesi dolan paketleri temizle


             DateTime firstptime = packets.ToList().Where(i =>
                    i.Value.Type == newOne.Type).Where(i =>
                 i.Value.destIp == newOne.destIp).First().Value.TimeStamp;

              int totaltime = Convert.ToInt32(DateTime.Now.Subtract(firstptime).TotalSeconds);

              int pcount = packets.ToList().Where(i =>
                    i.Value.Type == newOne.Type).Count(i =>
                i.Value.destIp == newOne.destIp);
              int minplen = packets.ToList().Where(i =>
                i.Value.destIp == newOne.destIp
                ).Where(i =>
                    i.Value.Type == newOne.Type).Min(i =>
                  i.Value.lenght);

            double paverageLenght = packets.ToList().Where(i =>
                i.Value.destIp == newOne.destIp
                ).Where(i => i.Value.Type == newOne.Type).DefaultIfEmpty().Select(p => p.Value.lenght).Average();

            if (totaltime > 5 && minplen > 80 && (pcount / totaltime) * paverageLenght > 10240)
            {
                
                try
                {
                    if (possibleDDos.Where(i =>
                    i.Value.destIp == newOne.destIp).Where(i =>
                    i.Value.Type == newOne.Type).Last().Key >= 0)
                    {
                        int count=possibleDDos.Where(i =>
                           i.Value.destIp == newOne.destIp).Where(i =>
                    i.Value.Type == newOne.Type).Last().Value.count;
                        int avglen =
                        possibleDDos.Where(i =>
                          i.Value.destIp == newOne.destIp).Where(i =>
                    i.Value.Type == newOne.Type).Last().Value.Averagelenght;

                        possibleDDos.Where(i =>
                           i.Value.destIp == newOne.destIp).Where(i =>
                    i.Value.Type == newOne.Type).Last().Value.count = count + 1;
                        possibleDDos.Where(i =>
                          i.Value.destIp == newOne.destIp).Where(i =>
                    i.Value.Type == newOne.Type).Last().Value.Averagelenght =
                            Convert.ToInt32(((avglen + newOne.lenght) / (2)));

                    }
                    else
                    {
                        new Exception();
                    }
                }
                catch
                {
                    Packetx pAtk = new Packetx
                    {
                        TimeStamp = newOne.TimeStamp,
                        destIp = newOne.destIp,
                        destPort = newOne.destPort,
                        count = pcount,
                        Type = newOne.Type,
                        Averagelenght = Convert.ToInt32(paverageLenght),
                        //procName = newOne.procName,
                        procPid = newOne.procPid,
                        // procOwner = newOne.procOwner
                    };
                    possibleDDos.Add(DDosID, pAtk);
                    DDosID++;
                }
                newOne = new Packet();

                addDosList sad = new addDosList(addDosListx);
                atkList.Invoke(sad);
                
                //addDosList(possibleDDos);
               
               // addNode(newOne);
            }
            
        }

        public string GetProcessOwner(int processId)
        {
          /* string query = "Select * From Win32_Process Where ProcessID = " + processId;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection processList = searcher.Get();

            foreach (ManagementObject obj in processList)
            {
                string[] argList = new string[] { string.Empty, string.Empty };
                int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                if (returnVal == 0)
                {
                    // return user
                    return argList[0];
                }
            }*/

            return "NO OWNER";
        }
        private void OnAddTreeNode(TreeNode node)
        {
            //treeView.Nodes.Clear();
            treeView.Nodes.Add(node);
        }

        private void SnifferForm_Load(object sender, EventArgs e)
        {
            string strIP = null;
            //cmbInterfaces.Items.Add("127.0.0.1");
            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HosyEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                    strIP = ip.ToString();
                    cmbInterfaces.Items.Add(strIP);
                    if (IsIP(strIP))
                        cmbInterfaces.SelectedItem = strIP;
                }
            }            
        }

        private bool IsIP(string IP)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(IP, @"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$\b");
        }

        private void SnifferForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (bContinueCapturing)
            {
                bContinueCapturing = false;
                mainSocket.Close();
            }
        }
    }
}