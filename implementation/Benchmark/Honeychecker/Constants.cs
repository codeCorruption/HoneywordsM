namespace Honeychecker
{
    static class Constants
    {
        public const int LSPORT = 9050;
        public const int HCPORT = 9051;
        public const string LSIP = "127.0.0.1";
        public const string HCIP = "127.0.0.1";

        //public const string CURVE = "P-224";
        //public const string CURVE = "P-256";
        public const string CURVE = "P-521";

        public const int SKMAXSIZE = 64;

        //public const int ENCPASSLENGTH = 57; // For curve P-224, each point has 57 bytes long.
        //public const int ENCPASSLENGTH = 65; // For curve P-256, each point has 65 bytes long.
        public const int ENCPASSLENGTH = 133; // For curve P-512, each point has 133 bytes long.

        //public static string[] SWEETWORDS = { "qwe", "asd", "zxc", "wer", "sdf" };

        //public static string[] SWEETWORDS = { "qwe", "asd", "zxc", "wer", "sdf", "xcv", "ert", "dfg", "xcv", "rty" };

        //public static string[] SWEETWORDS = { "qwe", "asd", "zxc", "wer", "sdf", "xcv", "ert", "dfg", "xcv", "rty",
        //                                      "qwe1", "asd1", "zxc1", "wer1", "sdf1" };

        public static string[] SWEETWORDS = { "qwe", "asd", "zxc", "wer", "sdf", "xcv", "ert", "dfg", "xcv", "rty",
                                              "qwe1", "asd1", "zxc1", "wer1", "sdf1", "xcv1", "ert1", "dfg1", "xcv1",
                                              "rty1"
                                            };
    }
}
