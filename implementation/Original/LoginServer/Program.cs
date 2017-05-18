using System;
using System.Data.SqlClient;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace LoginServer
{
    class Program
    {
        public const int USERPORT = 9050;

        private static void Result(string time, string result, string id)
        {
            switch (result)
            {
                case "GRANT":
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write(" + ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(time + "   Access ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("GRANTED");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(" to user ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write(id);
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(".");
                    break;
                case "BREACH":
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write(" ! ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(time);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("   BREACH DETECTED");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(" while user ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write(id);
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(" requests access.");
                    break;
                case "DENY":
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write(" - ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(time + "   Access ");
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.Write("DENIED");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(" to user ");
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.Write(id);
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(".");
                    break;
                default:
                    break;
            }

            Console.ResetColor();
        }

        private static int Output(string text)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(" > ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(text);
            Console.ResetColor();
            return 60 - text.Length;
        }

        private static void Done(int padLength)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("[".PadLeft(padLength));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("DONE");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("]\n");
            Console.ResetColor();
        }

        static void Main(string[] args)
        {
            Output("Enhanced Honeywords System v1.0\n");
            Output("Distributed under the GNU General Public License (GPL)\n\n");
                       
            #region Network Connections
            int padBeforeDone = Output("Connecting to Honeychecker.");
            TcpClient server = new TcpClient("127.0.0.1", 9051);
            Done(padBeforeDone);

            NetworkStream ns = server.GetStream();
            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, USERPORT);
            Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            newsock.Bind(ipep);
            newsock.Listen(10);
            padBeforeDone = Output("Login Server started. Waiting for a client.");
            Done(padBeforeDone);
            Socket client = newsock.Accept();
            IPEndPoint clientep = (IPEndPoint)client.RemoteEndPoint;
            padBeforeDone = Output("Connected with " + clientep.Address.ToString() + " at port " + clientep.Port.ToString());
            Done(padBeforeDone);
            #endregion

            while (true)
            {
                byte[] data = new byte[1024];
                int recv = client.Receive(data);
                if (recv == 0)
                    break;

                string timestamp = DateTime.UtcNow.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);

                //Debug.WriteLine("{0}   Received {1} bytes of data.", timestamp, recv);

                int usernameLength = BitConverter.ToInt32(data, 0);
                string username = Encoding.UTF8.GetString(data, 4, usernameLength);
                string pwd = Encoding.UTF8.GetString(data, 4 + usernameLength, recv - (4 + usernameLength));

                SHA1Managed hasher = new SHA1Managed();
                byte[] pwdHash = hasher.ComputeHash(Encoding.UTF8.GetBytes(pwd)); // SHA1 hash of password is computed.

                Output(timestamp + "   " + clientep.Address.ToString() + ":" + clientep.Port.ToString() + " requested access with username: " + username + "\n");

                int id = 0;
                byte[] sweetbytes = null;

                string connStr = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=|DataDirectory|\credentials.mdf; Integrated Security=True; Connect Timeout=10;";
                using (SqlConnection conn = new SqlConnection(connStr))
                {
                    conn.Open();
                    using (SqlCommand command = new SqlCommand("SELECT * FROM Credentials WHERE username=@uname", conn))
                    {
                        command.Parameters.AddWithValue("@uname", username);
                        using (var rdr = command.ExecuteReader())
                        {
                            if (!rdr.HasRows)
                            {
                                Output("Access denied to invalid username: " + username + "\n");
                                data = Encoding.UTF8.GetBytes("Access denied. Reason: Wrong username!");
                                client.Send(data, data.Length, SocketFlags.None);
                                continue;
                            }

                            while (rdr.Read())
                            {
                                id = (int)rdr["Id"];
                                sweetbytes = (byte[])rdr["sweetbytes"];
                            }
                        }
                    }
                }

                int numberOfSweetwords = sweetbytes.Length / 20;    // Each pass is 43 bytes long.

                int index = 0;

                for (int i = 0; i < numberOfSweetwords; i++)
                {
                    index = i;

                    for (int j = 0; j < pwdHash.Length; j++) // Each sweetword has 43 bytes long, I hope :)
                    {
                        if (sweetbytes[i * pwdHash.Length + j] != pwdHash[j])
                        {
                            index = -1;
                            break;
                        }
                    }

                    if (index > -1)
                        break;
                }

                string result = "";

                if (index > -1) // The index is found.
                {
                    byte[] checkMessage = new byte[4 + 4];
                    Buffer.BlockCopy(BitConverter.GetBytes(id), 0, checkMessage, 0, 4); // id
                    Buffer.BlockCopy(BitConverter.GetBytes(index), 0, checkMessage, 4, 4); // index
                    ns.Write(checkMessage, 0, checkMessage.Length);
                    ns.Flush();

                    byte[] datahc = new byte[1024];
                    int recvhc = ns.Read(datahc, 0, datahc.Length);
                    int resulthc = BitConverter.ToInt32(datahc, 0);
                    
                    timestamp = DateTime.UtcNow.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
                    
                    switch (resulthc)
                    {
                        case 0:
                            Output(timestamp + "   Access GRANTED to " + username + ".\n");
                            result = "Access granted.";
                            break;
                        case 1:
                            Output(timestamp + "   BREACH DETECTED while " + username + " requests access.\n");
                            result = "Access denied. Reason: Wrong password!";
                            break;
                    }
                }
                else
                {
                    Output(timestamp + "   Access DENIED to " + clientep.Address.ToString() + ":" + clientep.Port.ToString() + ".\n");
                    result = "Access denied. Reason: Wrong password!";
                    break;
                }
                
                data = Encoding.UTF8.GetBytes(result);
                client.Send(data, data.Length, SocketFlags.None);
            }

            Console.WriteLine("Disconnected from {0}", clientep.Address);
            client.Close();
            newsock.Close();

            ns.Close();
            server.Close();
            Console.ReadKey();
        }
    }
}
