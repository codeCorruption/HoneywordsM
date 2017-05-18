using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace User
{
    class Program
    {
        private const int LSPORT = 9050;

        // We define OTP(n) = n.
        private static BigInteger GenerateOTP(int n)
        {
            return new BigInteger(n.ToString());
        }

        private static byte[] EncryptPassword(string password, BigInteger rnBar, ECPoint pk)
        {
            SHA1Managed hasher = new SHA1Managed();
            byte[] pwdHash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password)); // SHA1 hash of password is computed.

            X9ECParameters ecParams = SecNamedCurves.GetByName("sect163k1"); // Picking up the elliptic curve.
            BigInteger groupOrder = ecParams.N;
            BigInteger w = (new BigInteger(pwdHash)).Mod(groupOrder); // Password is mapped to a big integer.
            w = w.Multiply(rnBar);
            return pk.Multiply(w).GetEncoded(); // pk^(w*rn) = ((g^sk)^w)^rnbar)
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

                int nMinusOne = 0;
                BigInteger RnMinusOneBar = null;
                ECPoint pk = null;

                string connStr = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=|DataDirectory|\clientdb.mdf; Integrated Security=True; Connect Timeout=10;";
                using (SqlConnection con = new SqlConnection(connStr))
                {
                    con.Open();
                    using (SqlCommand command = new SqlCommand("SELECT nMinusOne, RnMinusOneBar, pk FROM AuxValues WHERE username=@uname", con))
                    {
                        command.Parameters.AddWithValue("@uname", username);
                        using (var rdr = command.ExecuteReader())
                        {
                            if (!rdr.HasRows)
                            {
                                Output("AuxValues cannot been found for user: " + username + "\n");
                                continue;
                            }

                            while (rdr.Read())
                            {
                                nMinusOne = (int)rdr["nMinusOne"];
                                RnMinusOneBar = new BigInteger((byte[])rdr["RnMinusOneBar"]);
                                pk = SecNamedCurves.GetByName("sect163k1").Curve.DecodePoint((byte[])rdr["pk"]);
                            }
                        }
                    }
                }
                
                BigInteger rn = GenerateOTP(nMinusOne + 1);
                BigInteger rnBar = RnMinusOneBar.Multiply(rn);

                Output("Enter password: ");
                string password = Console.ReadLine();
                
                byte[] usernameInBytes = Encoding.UTF8.GetBytes(username);
                byte[] encPass = EncryptPassword(password, rnBar, pk);
                data = new byte[usernameInBytes.Length + encPass.Length];
                Buffer.BlockCopy(encPass, 0, data, 0, encPass.Length);
                Buffer.BlockCopy(usernameInBytes, 0, data, encPass.Length, usernameInBytes.Length);

                Stopwatch sw = new Stopwatch(); // For benchmarking purposes we create an instance of a Stopwatch
                sw.Start();
                ns.Write(data, 0, data.Length);
                ns.Flush();

                data = new byte[1024];
                int recv = ns.Read(data, 0, data.Length);
                stringData = Encoding.UTF8.GetString(data, 0, recv);
                sw.Stop(); // We measure the time between sending a login request and receiving a response.
                Output(stringData + " Elapsed time: " + sw.Elapsed.TotalMilliseconds + " ms.\n");
                
                // If Honeychecker is involved, update local storage.
                if (stringData.Equals("Access denied. Reason: Wrong password!") ||
                    stringData.Equals("Access granted."))
                {
                    using (SqlConnection con = new SqlConnection(connStr))
                    {
                        con.Open();
                        using (SqlCommand cmd = new SqlCommand("UPDATE AuxValues SET nMinusOne=@n, RnMinusOneBar=@rmnob WHERE username=@uname", con))
                        {
                            cmd.Parameters.AddWithValue("@n", nMinusOne + 1); // n
                            cmd.Parameters.AddWithValue("@rmnob", rnBar.ToByteArray());
                            cmd.Parameters.AddWithValue("@uname", username);
                            cmd.ExecuteNonQuery();
                        }
                    }
                }
            }

            Output("Disconnecting from server...\n");
            ns.Close();
            server.Close();
            Console.Write("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
