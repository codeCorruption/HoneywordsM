using System;
using System.Data.SqlClient;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Honeychecker;
using System.Diagnostics;

namespace LoginServer
{
    class Program
    {        
        static void Main(string[] args)
        {
            Console.WriteLine();
            Utils.Output("Enhanced Honeywords System v1.0\n");
            Utils.Output("Distributed under the GNU General Public License (GPL)\n\n");
                       
            #region Network Connections
            int padBeforeDone = Utils.Output("Connecting to Honeychecker.");
            TcpClient server = new TcpClient("127.0.0.1", Constants.HCPORT);
            Utils.Done(padBeforeDone);

            NetworkStream ns = server.GetStream();
            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, Constants.LSPORT);
            Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            newsock.Bind(ipep);
            newsock.Listen(10);
            padBeforeDone = Utils.Output("Login Server started. Waiting for a client.");
            Utils.Done(padBeforeDone);
            Socket client = newsock.Accept();
            IPEndPoint clientep = (IPEndPoint)client.RemoteEndPoint;
            padBeforeDone = Utils.Output("Connected with " + clientep.Address.ToString() + " at port " + clientep.Port.ToString());
            Utils.Done(padBeforeDone);
            Console.WriteLine();
            #endregion

            Stopwatch sw = new Stopwatch();

            int numberOfRequests = 0;

            while (true)
            {
                byte[] data = new byte[1024];
                int recv = client.Receive(data);
                if (recv == 0)
                    break;

                if (numberOfRequests == 1)
                    sw.Reset();

                numberOfRequests++;
                sw.Start();

                string username = Encoding.UTF8.GetString(data, Constants.ENCPASSLENGTH, recv - Constants.ENCPASSLENGTH);
                byte[] c = new byte[Constants.ENCPASSLENGTH];
                Buffer.BlockCopy(data, 0, c, 0, c.Length);

                int id = 0;
                byte[] sweetbytes = null;

                sw.Stop();

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
                                Utils.Output("Access denied to invalid username: " + username + "\n");
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

                sw.Start();

                int numberOfSweetwords = sweetbytes.Length / Constants.ENCPASSLENGTH;

                int index = -1;

                for (int i = 0; i < numberOfSweetwords; i++)
                {
                    bool found = true;

                    for (int j = 0; j < Constants.ENCPASSLENGTH; j++)
                    {
                        if (sweetbytes[i * Constants.ENCPASSLENGTH + j] != c[j])
                        {
                            found = false;
                            break;
                        }
                    }

                    if (found == true)
                    {
                        index = i;
                        break;
                    }
                }

                string result = "";

                if (index > -1) // The index is found.
                {
                    byte[] checkMessage = new byte[4 + 4 + sweetbytes.Length];
                    Buffer.BlockCopy(BitConverter.GetBytes(id), 0, checkMessage, 0, 4); // id
                    Buffer.BlockCopy(BitConverter.GetBytes(index), 0, checkMessage, 4, 4); // index
                    Buffer.BlockCopy(sweetbytes, 0, checkMessage, 8, sweetbytes.Length); // sweetbytes, i.e., encrypted passwords

                    sw.Stop();

                    ns.Write(checkMessage, 0, checkMessage.Length);
                    ns.Flush();

                    byte[] datahc = new byte[3072]; // Actual max value is 2260 + 4
                    int recvhc = ns.Read(datahc, 0, datahc.Length);

                    sw.Start();

                    int resulthc = BitConverter.ToInt32(datahc, 0);

                    byte[] updatedEncPasswords = new byte[sweetbytes.Length];
                    Buffer.BlockCopy(datahc, 4, updatedEncPasswords, 0, updatedEncPasswords.Length); // re-encrypted passwords
                    // we do not shuffle yet.
                    
                    switch (resulthc)
                    {
                        case 0:
                            result = "Access granted.";
                            break;
                        case 1:
                            result = "Access denied. Reason: Breach detected!";
                            break;
                    }

                    sw.Stop();

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
                    result = "Access denied. Reason: Wrong password!";
                }
                
                data = Encoding.UTF8.GetBytes(result);
                client.Send(data, data.Length, SocketFlags.None);
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("   Number of Requests     Total Time");
            Console.WriteLine("   ------------------     --------------");
            Console.WriteLine("   {0, -18}     {1,-14}", numberOfRequests, sw.Elapsed.TotalMilliseconds);

            Console.ResetColor();


            Console.WriteLine("Disconnected from {0}", clientep.Address);
            client.Close();
            newsock.Close();

            ns.Close();
            server.Close();
            Console.ReadKey();
        }
    }
}
