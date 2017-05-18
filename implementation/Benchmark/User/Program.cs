using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Data.SqlClient;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Honeychecker;

namespace User
{
    class Program
    {
        private static string conStr = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=|DataDirectory|\clientdb.mdf; Integrated Security=True; Connect Timeout=10;";

        private static byte[] EncryptPassword(string password, BigInteger RnBar, ECPoint pk)
        {
            SHA1Managed hasher = new SHA1Managed();
            byte[] pwdHash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password)); // SHA1 hash of password is computed.

            X9ECParameters ecParams = NistNamedCurves.GetByName(Constants.CURVE); // Picking up the elliptic curve.
            BigInteger groupOrder = ecParams.N;
            BigInteger w = (new BigInteger(pwdHash)).Mod(groupOrder); // Password is mapped to a big integer.
            w = w.Multiply(RnBar);
            return pk.Multiply(w).GetEncoded(); // pk^(w*rn) = ((g^sk)^w)^rnbar)
        }

        private static void UpdateLocalDB(int n, BigInteger rnBar, string username)
        {
            using (SqlConnection con = new SqlConnection(conStr))
            {
                con.Open();
                using (SqlCommand cmd = new SqlCommand("UPDATE AuxValues SET n=@n, PrevRnBar=@rmnob WHERE username=@uname", con))
                {
                    cmd.Parameters.AddWithValue("@n", n);
                    cmd.Parameters.AddWithValue("@rmnob", rnBar.ToByteArray());
                    cmd.Parameters.AddWithValue("@uname", username);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        private static bool ReadAuxValues(string username, ref int n, ref BigInteger PrevRnBar, ref ECPoint pk)
        {
            using (SqlConnection con = new SqlConnection(conStr))
            {
                con.Open();
                using (SqlCommand command = new SqlCommand("SELECT n, PrevRnBar, pk FROM AuxValues WHERE username=@uname", con))
                {
                    command.Parameters.AddWithValue("@uname", username);
                    using (var rdr = command.ExecuteReader())
                    {
                        if (!rdr.HasRows)
                        {
                            Utils.Output("AuxValues cannot been found for user: " + username + "\n");
                            return false;
                        }

                        while (rdr.Read())
                        {
                            n = (int)rdr["n"];
                            PrevRnBar = new BigInteger((byte[])rdr["PrevRnBar"]);
                            pk = NistNamedCurves.GetByName(Constants.CURVE).Curve.DecodePoint((byte[])rdr["pk"]);
                        }
                    }
                }
            }

            return true;
        }

        private static void VerifyUser(NetworkStream ns, string username, string password)
        {
            int n = 0;
            BigInteger PrevRnBar = null;
            ECPoint pk = null;

            bool readResults = ReadAuxValues(username, ref n, ref PrevRnBar, ref pk);

            if (!readResults)
                return;

            BigInteger rn = Utils.GenerateOTP(n);
            BigInteger rnBar = PrevRnBar.Multiply(rn);

            byte[] usernameInBytes = Encoding.UTF8.GetBytes(username);
            byte[] encPass = EncryptPassword(password, rnBar, pk);
            byte[] data = new byte[usernameInBytes.Length + encPass.Length];
            Buffer.BlockCopy(encPass, 0, data, 0, encPass.Length);
            Buffer.BlockCopy(usernameInBytes, 0, data, encPass.Length, usernameInBytes.Length);

            ns.Write(data, 0, data.Length);
            ns.Flush();

            data = new byte[1024];
            int recv = ns.Read(data, 0, data.Length);
            string stringData = Encoding.UTF8.GetString(data, 0, recv);
            
            // If Honeychecker is involved, update local storage.
            if (stringData.Equals("Access granted.") ||
                stringData.Equals("Access denied. Reason: Breach detected!"))
            {
                UpdateLocalDB(n + 1, rnBar, username);
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine();
            Utils.Output("Enhanced Honeywords System v1.0\n");
            Utils.Output("Distributed under the GNU General Public License (GPL)\n\n");

            int padBeforeDone = Utils.Output("Connecting to Login Server.");

            TcpClient server = new TcpClient(Constants.LSIP, Constants.LSPORT);
            NetworkStream ns = server.GetStream();
            
            Utils.Done(padBeforeDone);
            Console.WriteLine();

            VerifyUser(ns, "ziya", "qwe"); // grant access

            for (int i = 0; i < 50; i++)
            {
                VerifyUser(ns, "ziya", "qwe"); // grant access
                VerifyUser(ns, "itzel", "qwe"); // breach
                //VerifyUser(ns, "gabriele", "asdasd"); // wrong password, definitely much faster than the above two.
            }
            
            Utils.Output("Disconnecting from server...\n");
            ns.Close();
            server.Close();
            Console.Write("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
