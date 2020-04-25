using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CDiChain.EncodingCryption
{
    public partial class CryptionAlgorithm
    {
        public static class DES
        {
            /// <summary>
            /// 加密
            /// </summary>
            /// <param name="text">要加密的字符串</param>
            /// <param name="password">密码,16位或32位字符串</param>
            /// <param name="iv">向量,16字节的字符串</param>
            /// <returns>加密后的Byte数组, 可以通过使用扩展方法.ToHex() 或 .ToBase64()来转换为字符串</returns>
            public static byte[] EncryptText(string plaintext, string password, string iv)
            {

                return EncryptText(plaintext, Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(iv));
            }

            /// <summary>
            /// DES加密字符串
            /// </summary>
            /// <param name="text">要加密的字符串</param>
            /// <param name="password">密码,16字节或32字节的数组</param>
            /// <param name="iv">向量,16字节的数组</param>
            /// <returns>加密后的Byte数组, 可以通过使用扩展方法.ToHex() 或 .ToBase64()来转换为字符串</returns>
            public static byte[] EncryptText(string plaintext, byte[] password, byte[] iv)
            {

                byte[] buffer = Encoding.UTF8.GetBytes(plaintext);
                MemoryStream ms = new MemoryStream();
                DESCryptoServiceProvider tdes = new DESCryptoServiceProvider();
                CryptoStream encStream = new CryptoStream(ms, tdes.CreateEncryptor(password, iv), CryptoStreamMode.Write);
                encStream.Write(buffer, 0, buffer.Length);
                encStream.FlushFinalBlock();
                return ms.ToArray();
            }

            /// <summary>
            /// 解密
            /// </summary>
            /// <param name="ciphertext">密文</param>
            /// <param name="password">密码,16位或32位字符串</param>
            /// <param name="iv">向量,16字节的字符串</param>
            /// <returns>原文</returns>
            public static string DecryptText(string ciphertext, string password, string iv)
            {
                return DecryptText(ciphertext, Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(iv));
            }

            /// <summary>
            /// 解密
            /// </summary>
            /// <param name="ciphertext">密文</param>
            /// <param name="password">密码,16字节或32字节的数组</param>
            /// <param name="iv">向量,16字节的数组</param>
            /// <returns>原文</returns>
            public static string DecryptText(string ciphertext, byte[] password, byte[] iv)
            {
                byte[] buffer = Convert.FromBase64String(ciphertext);
                MemoryStream ms = new MemoryStream();
                DESCryptoServiceProvider tdes = new DESCryptoServiceProvider();
                CryptoStream encStream = new CryptoStream(ms, tdes.CreateDecryptor(password, iv), CryptoStreamMode.Write);
                encStream.Write(buffer, 0, buffer.Length);
                encStream.FlushFinalBlock();
                return Encoding.UTF8.GetString(ms.ToArray());
            }

            #region DES文件加密
            /// <summary>
            /// DES文件加密
            /// </summary>
            /// <param name="inFilePath">加密文件地址</param>
            /// <param name="outFilePath">加密后的文件地址</param>
            /// <param name="password">密钥(建议长度为8字节)</param>
            /// <param name="iv">向量(建议长度为8字节)</param>
            public static void EncryptFile(string inFilePath, string outFilePath, string password, string iv)
            {
                byte[] desKey = Encoding.UTF8.GetBytes(password);
                byte[] desIv = Encoding.UTF8.GetBytes(iv);

                EncryptFile(inFilePath, outFilePath, desKey, desIv);
            }

            /// <summary>
            /// DES文件加密
            /// </summary>
            /// <param name="inFilePath">加密文件地址</param>
            /// <param name="outFilePath">加密后的文件地址</param>
            /// <param name="password">密钥(建议长度为8字节)</param>
            /// <param name="iv">向量(建议长度为8字节)</param>
            public static void EncryptFile(string inFilePath, string outFilePath, byte[] password, byte[] iv)
            {
                using (FileStream ins = new FileStream(inFilePath, FileMode.Open, FileAccess.Read))
                {
                    using (FileStream outs = new FileStream(outFilePath, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        outs.SetLength(0);
                        byte[] buffer = new byte[1024 * 512];
                        long readLen = 0;
                        long totlen = ins.Length;
                        int len;
                        System.Security.Cryptography.DES des = new DESCryptoServiceProvider();
                        using (CryptoStream encStream = new CryptoStream(outs, des.CreateEncryptor(password, iv), CryptoStreamMode.Write))
                        {
                            while (readLen < totlen)
                            {
                                len = ins.Read(buffer, 0, buffer.Length);
                                encStream.Write(buffer, 0, len);
                                readLen += len;
                            }
                        }
                    }
                }
            }

            #endregion

            #region DES文件解密
            /// <summary>
            /// DES文件解密
            /// </summary>
            /// <param name="inFilePath">需要解密的文件地址</param>
            /// <param name="outFilePath">解密后的文件地址</param>
            /// <param name="password">密钥(建议长度为8字节)</param>
            /// <param name="iv">向量(建议长度为8字节)</param>
            public static void DecryptFile(string inFilePath, string outFilePath, string password, string iv)
            {
                byte[] desKey = Encoding.UTF8.GetBytes(password);
                byte[] desIv = Encoding.UTF8.GetBytes(iv);
                DecryptFile(inFilePath, outFilePath, desKey, desIv);
            }

            /// <summary>
            /// DES文件解密
            /// </summary>
            /// <param name="inFilePath">需要解密的文件地址</param>
            /// <param name="outFilePath">解密后的文件地址</param>
            /// <param name="password">密钥(建议长度为8字节)</param>
            /// <param name="iv">向量(建议长度为8字节)</param>
            public static void DecryptFile(string inFilePath, string outFilePath, byte[] password, byte[] iv)
            {
                using (FileStream ins = new FileStream(inFilePath, FileMode.Open, FileAccess.Read))
                {
                    using (FileStream outs = new FileStream(outFilePath, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        outs.SetLength(0);
                        byte[] buffer = new byte[1024 * 512];
                        long readLen = 0;
                        long totlLen = ins.Length;
                        int len;
                        System.Security.Cryptography.DES des = new DESCryptoServiceProvider();
                        using (var dencStream = new CryptoStream(outs, des.CreateDecryptor(password, iv), CryptoStreamMode.Write))
                        {
                            while (readLen < totlLen)
                            {
                                len = ins.Read(buffer, 0, buffer.Length);
                                dencStream.Write(buffer, 0, len);
                                readLen += len;
                            }
                        }
                    }
                }
            }
            #endregion

        }

    }
}
