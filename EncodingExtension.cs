using CDiChain.EncodingCryption.Encoder;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

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

        public static bool IsHexString(this string str)
        {
            if (string.IsNullOrEmpty(str))
            {
                return false;
            }

            Regex regex = new Regex("[^0-9A-Fa-f]");
            var mat = regex.Match(str);
            return !mat.Success;
        }
    }
}
