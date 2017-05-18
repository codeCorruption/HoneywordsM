using System;
using System.Data.SqlClient;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
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

                string username = Encoding.UTF8.GetString(data, 43, recv-43);
                byte[] c = new byte[43];
                Buffer.BlockCopy(data, 0, c, 0, c.Length);

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

                int numberOfSweetwords = sweetbytes.Length / 43;    // Each pass is 43 bytes long.

                int index = 0;

                for (int i = 0; i < numberOfSweetwords; i++)
                {
                    index = i;

                    for (int j = 0; j < 43; j++) // Each sweetword has 43 bytes long, I hope :)
                    {
                        if (sweetbytes[i * 43 + j] != c[j])
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
                    byte[] checkMessage = new byte[4 + 4 + 430];
                    Buffer.BlockCopy(BitConverter.GetBytes(id), 0, checkMessage, 0, 4); // id
                    Buffer.BlockCopy(BitConverter.GetBytes(index), 0, checkMessage, 4, 4); // index
                    Buffer.BlockCopy(sweetbytes, 0, checkMessage, 8, 430); // sweetbytes, i.e., encrypted passwords
                    ns.Write(checkMessage, 0, checkMessage.Length);
                    ns.Flush();

                    byte[] datahc = new byte[1024];
                    int recvhc = ns.Read(datahc, 0, datahc.Length);
                    int resulthc = BitConverter.ToInt32(datahc, 0);

                    byte[] updatedEncPasswords = new byte[430];
                    Buffer.BlockCopy(datahc, 4, updatedEncPasswords, 0, 430); // re-encrypted passwords
                    // we do not shuffle yet.

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

                    using (SqlConnection conn = new SqlConnection(connStr))
                    {
                        conn.Open();
                        using (SqlCommand command = new SqlCommand("UPDATE Credentials SET sweetbytes=@sweetbytes WHERE username=@uname", conn))
                        {
                            command.Parameters.AddWithValue("@uname", username);
                            command.Parameters.AddWithValue("@sweetbytes", updatedEncPasswords);
                            command.ExecuteNonQuery();
                        }
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
