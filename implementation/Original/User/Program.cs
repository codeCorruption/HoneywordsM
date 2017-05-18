using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace User
{
    class Program
    {
        private const int LSPORT = 9050;
        
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
            Console.WriteLine("]");
            Console.ResetColor();
        }

        static void Main(string[] args)
        {
            Output("Enhanced Honeywords System v1.0\n");
            Output("Distributed under the GNU General Public License (GPL)\n\n");
            int padBeforeDone = Output("Connecting to Login Server.");

            TcpClient server = new TcpClient("127.0.0.1", LSPORT);    // We define the port number as 9050 in the beginning.
            Done(padBeforeDone);
            Console.WriteLine();

            NetworkStream ns = server.GetStream();
            byte[] data;
            string stringData;

            while (true)
            {
                Output("Enter username: ");
                string username = Console.ReadLine();

                if (username == "")
                    break;
                        
                Output("Enter password: ");
                string password = Console.ReadLine();
                
                byte[] usernameInBytes = Encoding.UTF8.GetBytes(username);
                byte[] pwdInBytes = Encoding.UTF8.GetBytes(password);
                data = new byte[4 + usernameInBytes.Length + pwdInBytes.Length];

                Buffer.BlockCopy(BitConverter.GetBytes(usernameInBytes.Length), 0, data, 0, 4);
                Buffer.BlockCopy(usernameInBytes, 0, data, 4, usernameInBytes.Length);
                Buffer.BlockCopy(pwdInBytes, 0, data, 4 + usernameInBytes.Length, pwdInBytes.Length);

                Stopwatch sw = new Stopwatch(); // For benchmarking purposes we create an instance of a Stopwatch
                sw.Start();
                ns.Write(data, 0, data.Length);
                ns.Flush();

                data = new byte[1024];
                int recv = ns.Read(data, 0, data.Length);
                stringData = Encoding.UTF8.GetString(data, 0, recv);
                sw.Stop(); // We measure the time between sending a login request and receiving a response.
                Output(stringData + " Elapsed time: " + sw.Elapsed.TotalMilliseconds + " ms.\n");
            }

            Output("Disconnecting from server...\n");
            ns.Close();
            server.Close();
            Console.Write("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
