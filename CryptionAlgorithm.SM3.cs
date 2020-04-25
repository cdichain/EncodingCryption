using CDiChain.EncodingCryption.SMCryption;
using System.Text;

namespace CDiChain.EncodingCryption
{
    public partial class CryptionAlgorithm
    {
        public static class SM3
        {
            /// <summary>
            /// 国密SM3摘要算法
            /// </summary>
            /// <param name="plaintext">原文</param>
            /// <returns>32个字符的小写摘要字符串</returns>
#pragma warning disable IDE1006 // 命名样式
            public static string hash(string plaintext)
#pragma warning restore IDE1006 // 命名样式
            {
                var sm3 = new SM3Algorithm(Encoding.UTF8);

                return sm3.Hash(plaintext).ToLower();
            }

            /// <summary>
            /// 国密SM3摘要算法
            /// </summary>
            /// <param name="plaintext">原文</param>
            /// <returns>32个字符的大写摘要字符串</returns>
            public static string HASH(string plaintext)
            {
                var sm3 = new SM3Algorithm(Encoding.UTF8);

                return sm3.Hash(plaintext).ToUpper();
            }
        }
    }
}
