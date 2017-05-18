using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Honeychecker
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine();
            Utils.Output("Enhanced Honeywords System v1.0\n");
            Utils.Output("Distributed under the GNU General Public License (GPL)\n\n");

            #region Network Connections
            int padBeforeDone = Utils.Output("Starting network connections.");
            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, Constants.HCPORT);
            Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            newsock.Bind(ipep);
            newsock.Listen(10);
            Utils.Done(padBeforeDone);
            padBeforeDone = Utils.Output("Honeychecker started. Waiting for Login Server.");
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
                byte[] data = new byte[3072]; // Actual max value is expected 2260 + 4 + 4
                int recv = client.Receive(data);
                if (recv == 0)
                    break;

                if (numberOfRequests == 1)
                    sw.Reset();

                numberOfRequests++;
                sw.Start();
                
                int id = BitConverter.ToInt32(data, 0);
                int index = BitConverter.ToInt32(data, 4);
                byte[] sweetbytes = new byte[recv - (4 + 4)];
                Buffer.BlockCopy(data, 8, sweetbytes, 0, sweetbytes.Length); // sweetbytes, i.e., encrypted passwords

                int c = 0;
                int n = 0;

                sw.Stop();

                string connStr = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=|DataDirectory|\indexdb.mdf; Integrated Security=True; Connect Timeout=10;";
                using (SqlConnection conn = new SqlConnection(connStr))
                {
                    conn.Open();
                    using (SqlCommand command = new SqlCommand("SELECT indexOfPassword, n FROM IndexTable WHERE Id=@id", conn))
                    {
                        command.Parameters.AddWithValue("@Id", id);
                        using (var rdr = command.ExecuteReader())
                        {
                            if (!rdr.HasRows)
                            {
                                Utils.Output("Fatal error! Id cannot be found: " + id.ToString() +"\n");
                                Utils.Output("This may break the synchronization of OTPs!\n");
                                continue;
                            }

                            while (rdr.Read())
                            {
                                c = (int)rdr["indexOfPassword"];
                                n = (int)rdr["n"];
                            }
                        }
                    }
                }

                sw.Start();
                data = new byte[4 + sweetbytes.Length];

                if (index == c)
                    Buffer.BlockCopy(BitConverter.GetBytes(0), 0, data, 0, 4);
                else
                    Buffer.BlockCopy(BitConverter.GetBytes(1), 0, data, 0, 4);
                
                BigInteger rNplusOne = Utils.GenerateOTP(n);

                int numberOfSweetwords = sweetbytes.Length / Constants.ENCPASSLENGTH;

                for (int i = 0; i < numberOfSweetwords; i++)
                {
                    byte[] sweetword = new byte[Constants.ENCPASSLENGTH];
                    Buffer.BlockCopy(sweetbytes, i* sweetword.Length, sweetword, 0, sweetword.Length);
                    ECPoint swd = NistNamedCurves.GetByName(Constants.CURVE).Curve.DecodePoint(sweetword);
                    swd = swd.Multiply(rNplusOne);
                    sweetword = swd.GetEncoded();

                    Buffer.BlockCopy(sweetword, 0, sweetbytes, i* sweetword.Length, sweetword.Length);
                }

                
                Buffer.BlockCopy(sweetbytes, 0, data, 4, sweetbytes.Length);

                sw.Stop(); // We measure the time between sending a login request and receiving a response.

                using (SqlConnection con = new SqlConnection(connStr))
                {
                    con.Open();
                    using (SqlCommand cmd = new SqlCommand("UPDATE IndexTable SET n=@n WHERE Id=@id", con))
                    {
                        cmd.Parameters.AddWithValue("@n", n + 1);
                        cmd.Parameters.AddWithValue("@id", id);
                        cmd.ExecuteNonQuery();
                    }
                }
                
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
            Console.ReadKey();
        }
    }
}
