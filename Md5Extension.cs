using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CDiChain.EncodingCryption
{
    public static class Md5Extension
    {
        public static string MD5(this string sourceString)
        {
            return Encoding.UTF8.GetBytes(sourceString).MD5();
        }

        public static string md5(this string sourceString)
        {
            return sourceString.MD5().ToLower();
        }

        public static string md5(this byte[] bytes)
        {
            return bytes.MD5().ToLower();
        }

        public static string MD5(this byte[] bytes)
        {
            using (MD5 md5 = new MD5CryptoServiceProvider())
            {
                var output = md5.ComputeHash(bytes);
                return BitConverter.ToString(output).Replace("-", "").ToUpper();
            }
        }

        public static string MD5(this Stream stream)
        {
            using (MD5 md5 = new MD5CryptoServiceProvider())
            {
                var output = md5.ComputeHash(stream);
                return BitConverter.ToString(output).Replace("-", "").ToUpper();
            }
        }

        public static string md5(this Stream stream)
        {
            using (MD5 md5 = new MD5CryptoServiceProvider())
            {
                var output = md5.ComputeHash(stream);
                return BitConverter.ToString(output).Replace("-", "").ToLower();
            }
        }
    }
}
