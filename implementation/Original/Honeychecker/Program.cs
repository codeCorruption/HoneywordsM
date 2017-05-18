using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Honeychecker
{
    class Program
    {
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
            int padBeforeDone = Output("Starting network connections.");
            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 9051);
            Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            newsock.Bind(ipep);
            newsock.Listen(10);
            Done(padBeforeDone);
            padBeforeDone = Output("Honeychecker started. Waiting for Login Server.");
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
                
                int id = BitConverter.ToInt32(data, 0);
                int index = BitConverter.ToInt32(data, 4);
                int c = 0;
                
                string connStr = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=|DataDirectory|\indexdb.mdf; Integrated Security=True; Connect Timeout=10;";
                using (SqlConnection conn = new SqlConnection(connStr))
                {
                    conn.Open();
                    using (SqlCommand command = new SqlCommand("SELECT indexOfPassword FROM IndexTable WHERE Id=@id", conn))
                    {
                        command.Parameters.AddWithValue("@Id", id);
                        using (var rdr = command.ExecuteReader())
                        {
                            if (!rdr.HasRows)
                            {
                                Output("Fatal error! Id cannot be found: " + id.ToString() +"\n");
                                Output("This may break the synchronization!\n");
                                continue;
                            }

                            while (rdr.Read())
                            {
                                c = (int)rdr["indexOfPassword"];
                            }
                        }
                    }
                }
                
                string timestamp = DateTime.UtcNow.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);

                //padBeforeDone = Output(string.Format("{0}   Received {1} bytes of data.\n", timestamp, recv));

                Stopwatch sw = new Stopwatch(); // For benchmarking purposes we create an instance of a Stopwatch
                sw.Start();

                data = new byte[4];
                if (index == c)
                    Buffer.BlockCopy(BitConverter.GetBytes(0), 0, data, 0, 4);
                else
                    Buffer.BlockCopy(BitConverter.GetBytes(1), 0, data, 0, 4);
                
                sw.Stop(); // We measure the time between sending a login request and receiving a response.
              
                client.Send(data, data.Length, SocketFlags.None);

                Console.WriteLine("Elapsed time: " + sw.Elapsed.TotalMilliseconds + " ms."); // This outputs the elapsed time.
                //Debug.WriteLine("Elapsed time: " + sw.Elapsed.TotalMilliseconds + " ms."); // This outputs the elapsed time.
            }
            Console.WriteLine("Disconnected from {0}", clientep.Address);
            client.Close();
            newsock.Close();
            Console.ReadKey();
        }
    }
}
