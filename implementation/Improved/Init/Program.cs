using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace Init
{
    class Program
    {
        static byte[] EncryptPassword(string password, BigInteger sk)
        {
            SHA1Managed hasher = new SHA1Managed();
            byte[] pwdHash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password)); // SHA1 hash of password is computed.

            X9ECParameters spec = SecNamedCurves.GetByName("sect163k1"); // Picking up an elliptic curve.
            BigInteger N = spec.N; // Order of group
            ECPoint G = spec.G; // Base point
            BigInteger x = new BigInteger(pwdHash);
            x = x.Mod(N).Multiply(sk);
            return G.Multiply(x).GetEncoded();
        }

        static void Main(string[] args)
        {
            #region Creating (sk, pk) pair for Honeychecker
            byte[] secretKey = new byte[40]; // Will be truncated later.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(secretKey);
            X9ECParameters spec = SecNamedCurves.GetByName("sect163k1"); // Picking up an elliptic curve.
            BigInteger n = spec.N;
            ECPoint g = spec.G; // Base point
            BigInteger sk = new BigInteger(secretKey);
            sk = sk.Mod(n); // Truncating to fit in the group order.
            ECPoint pk = g.Multiply(sk);
            #endregion

            const int ENCPASSLENGTH = 43; // For curve sect163k1, each point has 43 bytes long.
            string[] users = { "ziya", "itzel", "gabriele", "peter" };
            string[] sweetwords = { "qwe", "asd", "zxc", "wer", "sdf", "xcv", "ert", "dfg", "xcv", "rty" };
            byte[] encPass = new byte[ENCPASSLENGTH];
            byte[] sweetbytes = new byte[ENCPASSLENGTH * sweetwords.Length];

            // Encrypting passwords
            for (int i = 0; i < sweetwords.Length; i++)
            {
                encPass = EncryptPassword(sweetwords[i], sk);
                System.Buffer.BlockCopy(encPass, 0, sweetbytes, i * encPass.Length, encPass.Length);
            }

            #region Initialiazation of Credentials DB
            string connStrLoginServerDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\Honeywords\LoginServer\bin\Debug\credentials.mdf; Integrated Security=True; Connect Timeout=10;";
            using (SqlConnection sqlConn = new SqlConnection(connStrLoginServerDB))
            {
                using (SqlCommand cmd = new SqlCommand())
                {
                    string sqlCreate = "DROP TABLE [dbo].[Credentials] " +
                                       "CREATE TABLE [dbo].[Credentials] (" +
                                       "[Id]         INT              IDENTITY (1, 1) NOT NULL," +
                                       "[username]   NVARCHAR (50)    NOT NULL," +
                                       "[sweetbytes] VARBINARY (1024) NOT NULL," +
                                       "PRIMARY KEY CLUSTERED ([Id] ASC));";

                    cmd.Connection = sqlConn;
                    cmd.CommandText = sqlCreate;
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();

                    for (int i = 0; i < users.Length; i++)
                    {
                        string username = users[i];
                        string sqlQuery = "INSERT INTO Credentials (username, sweetbytes) VALUES (@username, @binaryValue)";
                        cmd.Parameters.Clear();
                        cmd.Connection = sqlConn;
                        cmd.CommandText = sqlQuery;
                        cmd.Parameters.Add("@username", SqlDbType.NVarChar).Value = username;
                        cmd.Parameters.Add("@binaryValue", SqlDbType.VarBinary, 430).Value = sweetbytes;

                        cmd.ExecuteNonQuery();                        
                    }
                    
                    cmd.Connection.Close();
                }
            }
            Console.WriteLine("Completed initializing Login Server Database.");
            #endregion

            #region Initialiazation of Honeychecker DB
            string connStrHoneyCheckerDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\Honeywords\Honeychecker\bin\Debug\indexdb.mdf; Integrated Security=True; Connect Timeout=10;";
            using (SqlConnection sqlConn = new SqlConnection(connStrHoneyCheckerDB))
            {
                using (SqlCommand cmd = new SqlCommand())
                {
                    string sqlCreate = "DROP TABLE [dbo].[IndexTable] " +
                                       "CREATE TABLE [dbo].[IndexTable] (" +
                                       "[Id]              INT            IDENTITY (1, 1) NOT NULL," +
                                       "[indexOfPassword] INT            NOT NULL," +
                                       "[sk]              VARBINARY (50) NOT NULL," +
                                       "[n]               INT            NOT NULL," +
                                       "PRIMARY KEY CLUSTERED ([Id] ASC));";

                    cmd.Connection = sqlConn;
                    cmd.CommandText = sqlCreate;
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();
                    
                    for (int i = 0; i < 4; i++)
                    {
                        string sqlQuery = "INSERT INTO IndexTable (indexOfPassword, sk, n) VALUES (@index, @sk, @n)";
                        cmd.Parameters.Clear();
                        cmd.Connection = sqlConn;
                        cmd.CommandText = sqlQuery;
                        cmd.Parameters.Add("@index", SqlDbType.Int).Value = i;
                        cmd.Parameters.Add("@sk", SqlDbType.VarBinary).Value = secretKey;
                        cmd.Parameters.Add("@n", SqlDbType.Int).Value = 1;
                        
                        cmd.ExecuteNonQuery();
                    }
                    cmd.Connection.Close();
                }
            }

            Console.WriteLine("Completed initializing Honeychecker Database.");
            #endregion

            #region Initialiazation of Client DB
            string connStrClientDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\Honeywords\User\bin\Debug\clientdb.mdf; Integrated Security=True; Connect Timeout=10;";

            using (SqlConnection sqlConn = new SqlConnection(connStrClientDB))
            {
                using (SqlCommand cmd = new SqlCommand())
                {
                    string sqlCreate = "DROP TABLE [dbo].[AuxValues] " +
                                       "CREATE TABLE [dbo].[AuxValues] (" +
                                       "[Id]            INT            IDENTITY (1, 1) NOT NULL," +
                                       "[username]      NVARCHAR (50)  NOT NULL," +
                                       "[nMinusOne]     INT            NOT NULL," +
                                       "[RnMinusOneBar] VARBINARY (50) NOT NULL," +
                                       "[pk]            VARBINARY (50) NOT NULL," +
                                       "PRIMARY KEY CLUSTERED ([Id] ASC));";

                    cmd.Connection = sqlConn;
                    cmd.CommandText = sqlCreate;

                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();

                    for (int i = 0; i < 4; i++)
                    {
                        string sqlQuery = "INSERT INTO AuxValues (username, nMinusOne, RnMinusOneBar, pk) VALUES (@username, @nMinusOne, @rnmob, @pk)";
                        cmd.Parameters.Clear();
                        cmd.Connection = sqlConn;
                        cmd.CommandText = sqlQuery;
                        cmd.Parameters.Add("@username", SqlDbType.VarChar).Value = users[i];
                        cmd.Parameters.Add("@nMinusOne", SqlDbType.Int).Value = 0;
                        cmd.Parameters.Add("@rnmob", SqlDbType.VarBinary).Value = (new BigInteger("1")).ToByteArray();
                        cmd.Parameters.Add("@pk", SqlDbType.VarBinary).Value = pk.GetEncoded();

                        cmd.ExecuteNonQuery();
                    }

                    cmd.Connection.Close();
                }
            }
            Console.WriteLine("Completed initializing Client Database.");
            #endregion

            Console.Write("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
