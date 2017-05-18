using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace Init
{
    class Program
    {
        static byte[] EncryptPassword(string password)
        {
            SHA1Managed hasher = new SHA1Managed();
            byte[] pwdHash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password)); // SHA1 hash of password is computed.
            return pwdHash;
        }

        static void Main(string[] args)
        {
            const int ENCPASSLENGTH = 20; // Each SHA1 hash has 20 bytes long.
            string[] users = { "ziya", "itzel", "gabriele", "peter" };
            string[] sweetwords = { "qwe", "asd", "zxc", "wer", "sdf", "xcv", "ert", "dfg", "xcv", "rty" };
            byte[] encPass = new byte[ENCPASSLENGTH];
            byte[] sweetbytes = new byte[ENCPASSLENGTH * sweetwords.Length];

            // Encrypting passwords
            for (int i = 0; i < sweetwords.Length; i++)
            {
                encPass = EncryptPassword(sweetwords[i]);
                System.Buffer.BlockCopy(encPass, 0, sweetbytes, i * encPass.Length, encPass.Length);
            }

            #region Initialiazation of Credentials DB
            string connStrLoginServerDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\OriginalHoneywords\LoginServer\bin\Debug\credentials.mdf; Integrated Security=True; Connect Timeout=10;";
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
            string connStrHoneyCheckerDB = @"Data Source=(LocalDB)\MSSQLLocalDB; AttachDbFilename=C:\Users\Ziya\Desktop\OriginalHoneywords\Honeychecker\bin\Debug\indexdb.mdf; Integrated Security=True; Connect Timeout=10;";
            using (SqlConnection sqlConn = new SqlConnection(connStrHoneyCheckerDB))
            {
                using (SqlCommand cmd = new SqlCommand())
                {
                    string sqlCreate = "DROP TABLE [dbo].[IndexTable] " +
                                       "CREATE TABLE [dbo].[IndexTable] (" +
                                       "[Id]              INT            IDENTITY (1, 1) NOT NULL," +
                                       "[indexOfPassword] INT            NOT NULL," +
                                       "PRIMARY KEY CLUSTERED ([Id] ASC));";

                    cmd.Connection = sqlConn;
                    cmd.CommandText = sqlCreate;
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();
                    
                    for (int i = 0; i < 4; i++)
                    {
                        string sqlQuery = "INSERT INTO IndexTable (indexOfPassword) VALUES (@index)";
                        cmd.Parameters.Clear();
                        cmd.Connection = sqlConn;
                        cmd.CommandText = sqlQuery;
                        cmd.Parameters.Add("@index", SqlDbType.Int).Value = i;
                        
                        cmd.ExecuteNonQuery();
                    }
                    cmd.Connection.Close();
                }
            }

            Console.WriteLine("Completed initializing Honeychecker Database.");
            #endregion

            Console.Write("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
