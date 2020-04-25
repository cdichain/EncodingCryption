using CDiChain.EncodingCryption.Encoder;
using System;
using System.Collections.Generic;
using System.Text;

namespace CDiChain.EncodingCryption
{
   public static class EncodingExtension
    {
        public static string ToBase64(this byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        public static string ToHexString(this byte[] bytes)
        {
            return Hex.ToHexString(bytes);
        }
    }
}
