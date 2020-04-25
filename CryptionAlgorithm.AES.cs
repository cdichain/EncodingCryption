using CDiChain.EncodingCryption.Encoder;
using CDiChain.EncodingCryption.SMCryption;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CDiChain.EncodingCryption
{
    public partial class CryptionAlgorithm
    {
        public static class AES
        {
            public static byte[] Encrypt_CBC(string plaintext, string key, string initializationVector,
                PaddingMode paddingMode = PaddingMode.Zeros, Encoding encoding = null)
            {
                return Encrypt(plaintext, key, initializationVector, paddingMode, CipherMode.CBC, encoding);
            }

            public static byte[] Encrypt_ECB(string plaintext, string key,
              PaddingMode paddingMode = PaddingMode.Zeros, Encoding encoding = null)
            {
                return Encrypt(plaintext, key, null, paddingMode, CipherMode.ECB, encoding);
            }

            private static byte[] Encrypt(string plaintext, string key, string initializationVector,
                PaddingMode paddingMode, CipherMode cipherMode, Encoding encoding)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                if (string.IsNullOrEmpty(plaintext))
                {
                    return new byte[0];
                }

                var plaintextBytes = encoding.GetBytes(plaintext);

                var keyBytes = encoding.GetBytes(key);

                var ivBytes = new byte[0];
                if (!string.IsNullOrEmpty(initializationVector))
                {
                    ivBytes = encoding.GetBytes(initializationVector);
                }

                return EncrypText(plaintextBytes, keyBytes, ivBytes, paddingMode, cipherMode);
            }

            public static string Decrypt(string ciphertext, string key, string initializationVector,
                PaddingMode paddingMode, CipherMode cipherMode, Encoding encoding)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                if (string.IsNullOrEmpty(ciphertext))
                {
                    return ciphertext;
                }

                var keyBytes = encoding.GetBytes(key);

                var ivBytes = new byte[0];
                if (!string.IsNullOrEmpty(initializationVector))
                {
                    ivBytes = encoding.GetBytes(initializationVector);
                }

                return Decryptext(GetCipherArray(ciphertext), keyBytes, ivBytes, paddingMode, cipherMode, encoding);
            }

            //把要解密的内容 转化为byte类型数据
            private static byte[] GetCipherArray(string ciphertext)
            {
                var reg = new Regex("[^0-9A-F]");
                var mat = reg.Match(ciphertext);
                if (mat.Success)
                {
                    return Convert.FromBase64String(ciphertext);
                }
                else
                {
                    return Hex.Decode(ciphertext);
                }
            }

            //加密
            private static byte[] EncrypText(byte[] plaintext, byte[] key, byte[] iv,
                PaddingMode paddingMode, CipherMode cipherMode)
            {
                try
                {
                    var _aes = new AesCryptoServiceProvider();
                    _aes.BlockSize = 128;
                    _aes.KeySize = key.Length * 8;
                    _aes.Key = key;
                    _aes.IV = iv;
                    _aes.Padding = paddingMode;
                    _aes.Mode = cipherMode;

                    var _crypto = _aes.CreateEncryptor(_aes.Key, _aes.IV);
                    var encrypted = _crypto.TransformFinalBlock(plaintext, 0,
                        plaintext.Length);

                    _crypto.Dispose();

                    return encrypted;
                }
                catch (Exception)
                {
                    throw;
                }
            }

            //解密
            private static string Decryptext(byte[] ciphertext, byte[] key, byte[] iv,
                PaddingMode paddingMode, CipherMode cipherMode, Encoding encoding)
            {
                try
                {
                    var _aes = new AesCryptoServiceProvider();
                    _aes.BlockSize = 128;
                    _aes.KeySize = key.Length * 8;
                    _aes.Key = key;
                    _aes.IV = iv;
                    _aes.Padding = paddingMode;
                    _aes.Mode = cipherMode;

                    var _crypto = _aes.CreateDecryptor(_aes.Key, _aes.IV);
                    var decrypted = _crypto.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                    _crypto.Dispose();

                    return encoding.GetString(decrypted);
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }
    }
}
