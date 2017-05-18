using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using Honeychecker;

namespace Init
{
    class Program
    {
        private static byte[] EncryptPassword(string password, BigInteger rnBar, ECPoint pk)
        {
            SHA1Managed hasher = new SHA1Managed();
            byte[] pwdHash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password)); // SHA1 hash of password is computed.

            X9ECParameters ecParams = NistNamedCurves.GetByName(Constants.CURVE); // Picking up the elliptic curve.
            BigInteger groupOrder = ecParams.N;
            BigInteger w = (new BigInteger(pwdHash)).Mod(groupOrder); // Password is mapped to a big integer.
            w = w.Multiply(rnBar);
            return pk.Multiply(w).GetEncoded(); // pk^(w*rn) = ((g^sk)^w)^rnbar)
        }

        static void Main(string[] args)
        {
            #region Creating (sk, pk) pair for Honeychecker
            byte[] secretKey = new byte[Constants.SKMAXSIZE]; // Will be truncated later.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(secretKey);
            X9ECParameters spec = NistNamedCurves.GetByName(Constants.CURVE); // Picking up an elliptic curve.
            BigInteger n = spec.N;
            ECPoint g = spec.G; // Base point
            BigInteger sk = new BigInteger(secretKey);
            sk = sk.Mod(n); // Truncating to fit in the group order.
            ECPoint pk = g.Multiply(sk);
            byte[] pkb = pk.GetEncoded();
            #endregion

            string[] users = { "ziya", "itzel", "gabriele", "peter" };
            string[] sweetwords = Constants.SWEETWORDS;
            byte[] encPass = new byte[Constants.ENCPASSLENGTH];
            byte[] sweetbytes = new byte[Constants.ENCPASSLENGTH * sweetwords.Length];

            // Encrypting passwords
            for (int i = 0; i < sweetwords.Length; i++)
            {
                encPass = EncryptPassword(sweetwords[i], new BigInteger("1"), pk);
                System.Buffer.BlockCopy(encPass, 0, sweetbytes, i * encPass.Length, encPass.Length);
            }

            #region Initialiazation of Credentials DB
            string connStrLoginServerDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\HoneywordsBenchmark\LoginServer\bin\Debug\credentials.mdf; Integrated Security=True; Connect Timeout=10;";
            using (SqlConnection sqlConn = new SqlConnection(connStrLoginServerDB))
            {
                using (SqlCommand cmd = new SqlCommand())
                {
                    string sqlCreate = "DROP TABLE [dbo].[Credentials] " +
                                       "CREATE TABLE [dbo].[Credentials] (" +
                                       "[Id]         INT              IDENTITY (1, 1) NOT NULL," +
                                       "[username]   NVARCHAR (50)    NOT NULL," +
                                       "[sweetbytes] VARBINARY (2660) NOT NULL," + // In the max case
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
                        cmd.Parameters.Add("@binaryValue", SqlDbType.VarBinary, sweetbytes.Length).Value = sweetbytes;

                        cmd.ExecuteNonQuery();                        
                    }
                }
            }
            Console.WriteLine("Completed initializing Login Server Database.");
            #endregion

            #region Initialiazation of Honeychecker DB
            string connStrHoneyCheckerDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\HoneywordsBenchmark\Honeychecker\bin\Debug\indexdb.mdf; Integrated Security=True; Connect Timeout=10;";
            using (SqlConnection sqlConn = new SqlConnection(connStrHoneyCheckerDB))
            {
                using (SqlCommand cmd = new SqlCommand())
                {
                    string sqlCreate = "DROP TABLE [dbo].[IndexTable] " +
                                       "CREATE TABLE [dbo].[IndexTable] (" +
                                       "[Id]              INT            IDENTITY (1, 1) NOT NULL," +
                                       "[indexOfPassword] INT            NOT NULL," +
                                       "[sk]              VARBINARY (64) NOT NULL," + // Actual max is 521 bits.
                                       "[n]               INT            NOT NULL," +
                                       "PRIMARY KEY CLUSTERED ([Id] ASC));";

                    cmd.Connection = sqlConn;
                    cmd.CommandText = sqlCreate;
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();
                    
                    for (int i = 0; i < users.Length; i++)
                    {
                        string sqlQuery = "INSERT INTO IndexTable (indexOfPassword, sk, n) VALUES (@index, @sk, @n)";
                        cmd.Parameters.Clear();
                        cmd.Connection = sqlConn;
                        cmd.CommandText = sqlQuery;
                        cmd.Parameters.Add("@index", SqlDbType.Int).Value = i;
                        cmd.Parameters.Add("@sk", SqlDbType.VarBinary, secretKey.Length).Value = secretKey;
                        cmd.Parameters.Add("@n", SqlDbType.Int).Value = 2;
                        
                        cmd.ExecuteNonQuery();
                    }
                }
            }

            Console.WriteLine("Completed initializing Honeychecker Database.");
            #endregion

            #region Initialiazation of Client DB
            string connStrClientDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\HoneywordsBenchmark\User\bin\Debug\clientdb.mdf; Integrated Security=True; Connect Timeout=10;";

            using (SqlConnection sqlConn = new SqlConnection(connStrClientDB))
            {
                using (SqlCommand cmd = new SqlCommand())
                {
                    string sqlCreate = "DROP TABLE [dbo].[AuxValues] " +
                                       "CREATE TABLE [dbo].[AuxValues] (" +
                                       "[Id]            INT            IDENTITY (1, 1) NOT NULL," +
                                       "[username]      NVARCHAR (50)  NOT NULL," +
                                       "[n]             INT            NOT NULL," +
                                       "[PrevRnBar]     VARBINARY (50) NOT NULL," +
                                       "[pk]            VARBINARY (133) NOT NULL," + // Max case.
                                       "PRIMARY KEY CLUSTERED ([Id] ASC));";

                    cmd.Connection = sqlConn;
                    cmd.CommandText = sqlCreate;

                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();

                    for (int i = 0; i < users.Length; i++)
                    {
                        string sqlQuery = "INSERT INTO AuxValues (username, n, PrevRnBar, pk) VALUES (@username, @n, @rnbar, @pk)";
                        cmd.Parameters.Clear();
                        cmd.Connection = sqlConn;
                        cmd.CommandText = sqlQuery;
                        cmd.Parameters.Add("@username", SqlDbType.VarChar).Value = users[i];
                        cmd.Parameters.Add("@n", SqlDbType.Int).Value = 1;
                        cmd.Parameters.Add("@rnbar", SqlDbType.VarBinary).Value = (new BigInteger("1")).ToByteArray();
                        cmd.Parameters.Add("@pk", SqlDbType.VarBinary, pkb.Length).Value = pkb;

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
