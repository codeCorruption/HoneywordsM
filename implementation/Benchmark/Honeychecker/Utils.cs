using Org.BouncyCastle.Math;
using System;

namespace Honeychecker
{
    public static class Utils
    {
        public static BigInteger GenerateOTP(int n)
        {
            return new BigInteger(n.ToString());
        }

        public static void PrintResult(string time, string result, string id)
        {
            switch (result)
            {
                case "GRANT":
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write(" + ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(time + "     ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("ACCESS GRANTED      ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(id);
                    break;
                case "BREACH":
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write(" ! ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(time + "     ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("BREACH DETECTED     ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(id);
                    break;
                case "DENY":
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write(" - ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(time + "     ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("ACCESS DENIED       ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(id);
                    break;
                default:
                    break;
            }

            Console.ResetColor();
        }

        public static void PrintError(string error)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(" > ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(error);
            Console.ResetColor();
        }

        public static int Output(string text)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(" > ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(text);
            Console.ResetColor();
            return 71 - text.Length;
        }

        public static void Done(int padLength)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("[".PadLeft(padLength));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("DONE");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("]");
            Console.ResetColor();
        }

        public static void Fail(int padLength)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("[".PadLeft(padLength));
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("FAIL");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("]");
            Console.ResetColor();
        }
    }
}
