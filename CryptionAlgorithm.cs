using CDiChain.EncodingCryption.Encoder;
using CDiChain.EncodingCryption.SMCryption;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CDiChain.EncodingCryption
{
    public static class CryptionAlgorithm
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

        public static class SM4
        {

            public static string Encrypt_CBC_Base64(string plaintext, string keyInBase64Format, string initializationVectorInBase64Format,
                Encoding encoding = null)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                var keyBytes = Convert.FromBase64String(keyInBase64Format);
                var ivBytes = Convert.FromBase64String(initializationVectorInBase64Format);
                var sm4 = new SM4Algorithm(keyBytes, ivBytes, encoding, EncryptionResultTypes.Base64String);

                return sm4.EncryptString(plaintext, SM4Models.CBC);
            }

            public static string Encrypt_CBC_Hex(string plaintext, string keyInHexFormat, string initializationVectorInHexFormat,
             Encoding encoding = null)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                var keyBytes = Hex.Decode(keyInHexFormat);
                var ivBytes = Hex.Decode(initializationVectorInHexFormat);
                var sm4 = new SM4Algorithm(keyBytes, ivBytes, encoding, EncryptionResultTypes.HexString);

                return sm4.EncryptString(plaintext, SM4Models.CBC);
            }

            public static string Encrypt_ECB_Base64(string plaintext, string keyInBase64Format,
              Encoding encoding = null)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                var keyBytes = Convert.FromBase64String(keyInBase64Format);
                var sm4 = new SM4Algorithm(keyBytes, null, encoding, EncryptionResultTypes.Base64String);

                return sm4.EncryptString(plaintext, SM4Models.ECB);
            }

            public static string Encrypt_ECB_Hex(string plaintext, string keyInHexFormat,
             Encoding encoding = null)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                var keyBytes = Hex.Decode(keyInHexFormat);
                var sm4 = new SM4Algorithm(keyBytes, null, encoding, EncryptionResultTypes.HexString);

                return sm4.EncryptString(plaintext, SM4Models.ECB);
            }
        }

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

        public static class DES
        {
            /// <summary>
            /// 加密文件
            /// </summary>
            /// <param name="sourcePath">源文件</param>
            /// <param name="savePath">保存文件</param>
            /// <param name="keyString">密钥</param>
            public static string EncryptFileWithDES(string sourcePath, string keyString, string savePath = null)
            {
                if (string.IsNullOrEmpty(savePath))
                {
                    var extension = Path.GetExtension(sourcePath);
                    var pathWithoutExtension = sourcePath.Substring(0, sourcePath.Length - extension.Length);
                    savePath = pathWithoutExtension + "_DesEncrypted" + extension;
                    var i = 0;
                    while (File.Exists(savePath))
                    {
                        savePath = pathWithoutExtension + "_DesEncrypted" + i.ToString() + extension;
                        i++;
                    }
                }

                using (var des = GetDesCryptoServiceProvider(keyString))
                {
                    //创建加密器
                    var cryptoTransform = des.CreateEncryptor();
                    CryptoFileContent(sourcePath, savePath, cryptoTransform);
                }
                return savePath;
            }

            /// <summary>
            /// 解密文件
            /// </summary>
            /// <param name="sourcePath"></param>
            /// <param name="savePath"></param>
            /// <param name="keyString"></param>
            public static string DecryptFileWithDES(string sourcePath, string keyString, string savePath = null)
            {
                if (string.IsNullOrEmpty(savePath))
                {
                    var extension = Path.GetExtension(sourcePath);
                    var pathWithoutExtension = sourcePath.Substring(0, sourcePath.Length - extension.Length);
                    savePath = pathWithoutExtension + "_DesDecrypted" + extension;
                    var i = 0;
                    while (File.Exists(savePath))
                    {
                        savePath = pathWithoutExtension + "_DesDecrypted" + i.ToString() + extension;
                        i++;
                    }
                }

                using (var des = GetDesCryptoServiceProvider(keyString))
                {
                    //创建解密器
                    var cryptoTransform = des.CreateDecryptor();
                    CryptoFileContent(sourcePath, savePath, cryptoTransform);
                }

                return savePath;
            }


            /// <summary>
            /// 获取加密服务提供者
            /// </summary>
            /// <param name="keyStr"></param>
            /// <returns></returns>
            private static DESCryptoServiceProvider GetDesCryptoServiceProvider(string keyStr)
            {
                var keyBytes = Encoding.UTF8.GetBytes(keyStr);
                //计算指定字节组指定区域哈希值
                using (SHA1 sha = new SHA1Managed())
                {
                    var hash = sha.ComputeHash(keyBytes);
                    //加密密钥数组
                    var key = new byte[8];
                    for (var i = 0; i < 8; i++)
                    {
                        key[i] = hash[i];
                    }
                    //DES加密
                    var des = new DESCryptoServiceProvider { Key = key, IV = key };

                    return des;
                }
            }

            /// <summary>
            /// 加密或解密文件内容
            /// </summary>
            /// <param name="filePath"></param>
            /// <param name="savePath"></param>
            /// <param name="cryptoTransform"></param>
            private static void CryptoFileContent(string filePath, string savePath, ICryptoTransform cryptoTransform)
            {
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream =
                        new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        var inputByteArray = ReadFileAsBytes(filePath);
                        cryptoStream.Write(inputByteArray, 0, inputByteArray.Length);
                        cryptoStream.FlushFinalBlock();
                        SaveFile(savePath, memoryStream);
                    }
                }
            }

            /// <summary>
            /// 保存文件
            /// </summary>
            /// <param name="savePath"></param>
            /// <param name="memoryStream"></param>
            private static void SaveFile(string savePath, MemoryStream memoryStream)
            {
                using (var fileStream = File.OpenWrite(savePath))
                {
                    memoryStream.WriteTo(fileStream);
                }
            }

            /// <summary>
            /// 读取文件内容为字节
            /// </summary>
            /// <param name="filePath"></param>
            /// <returns></returns>
            private static byte[] ReadFileAsBytes(string filePath)
            {
                var fileStream = File.OpenRead(filePath);
                using (var binaryReader = new BinaryReader(fileStream))
                {
                    var inputByteArray = new byte[fileStream.Length];
                    _ = binaryReader.Read(inputByteArray, 0, inputByteArray.Length);
                    return inputByteArray;
                }
            }

        }

        public static class Number
        {
            private const string LowCaseLetters = "abcdefghijklmnopqrstuvwxyz";
            private const string UpperCaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            private const string NumberTable_8 = "01234567";
            private const string NumberTable_10 = "0123456789";
            private const string NumberTable_16 = "0123456789ABCDEF";
            private const string NumberTable_26 = UpperCaseLetters;
            private const string NumberTable_36 = NumberTable_10 + NumberTable_26;
            private const string NumberTable_42 = "!()-." + NumberTable_36 + "_";
            private const string NumberTable_62 = NumberTable_10 + LowCaseLetters + NumberTable_26;
            private const string NumberTable_64 = UpperCaseLetters + LowCaseLetters + NumberTable_10 + "+/";
            private const string NumberTableSafe_64 = UpperCaseLetters + LowCaseLetters + NumberTable_10 + "-_";
            private const string NumberTable_68 = "!()-." + NumberTable_62 + "_";

            public static string IntToString(int num, NumberSystem numberSystem, int minimumLength = 1)
            {
                var numberTable = GetNumberTable(numberSystem);

                var len = numberTable.Length;
                var n = num;
                var sb = new StringBuilder();
                while (true)
                {
                    // 取低位
                    var i = n % len;
                    _ = sb.Insert(0, numberTable[i]);
                    if (n < len)
                    {
                        break;
                    }

                    n /= len;
                }

                while (sb.Length < minimumLength)
                {
                    _ = sb.Insert(0, numberTable[0]);
                }

                return sb.ToString();
            }
            public static int StringToInt(string numStr, NumberSystem numberSystem)
            {
                var numberTable = GetNumberTable(numberSystem);
                if (numberTable == null)
                {
                    throw new NotSupportedException($"找不到{numberSystem.ToString()}的算法");
                }

                var len = numberTable.Length;
                var num = 0;

                foreach (var n in numStr)
                {
                    if (num == 0)
                    {
                        num = numberTable.IndexOf(n);
                    }
                    else
                    {
                        num = (num * len) + numberTable.IndexOf(n);
                    }
                }

                return num;
            }

            #region Int32

            public static uint Encode(uint number)
            {
                uint n = uint.MaxValue >> 1;
                uint r = 0;
                while (n > 0)
                {
                    if ((number & 1) == 1)
                    {
                        r += n;
                    }
                    n = n >> 1;
                    number = number >> 1;
                    if (number == 0)
                    {
                        break;
                    }
                }

                if (number > 0)
                {
                    r += 1;
                }

                return r;
            }

            public static uint Decode(uint number)
            {
                uint n = uint.MaxValue >> 1;
                uint d = 1;
                uint r = 0;
                while (n > 0)
                {
                    if (number >= n)
                    {
                        r += d;
                        number = number - n;
                        if (number <= 0)
                        {
                            break;
                        }
                    }

                    d = d << 1;
                    n = n >> 1;
                }

                if (number > 0)
                {
                    r += d;
                }

                return r;
            }

            #endregion Int32

            #region Int32

            public static int Encode(int number)
            {
                return (int)Encode((uint)number);
            }

            public static int Decode(int number)
            {
                return (int)Decode((uint)number);
            }

            #endregion Int32

            #region UInt64

            public static ulong Encode(ulong number)
            {
                ulong n = ulong.MaxValue >> 1;
                ulong r = 0;
                while (n > 0)
                {
                    if ((number & 1) == 1)
                    {
                        r += n;
                    }
                    n = n >> 1;
                    number = number >> 1;
                    if (number == 0)
                    {
                        break;
                    }
                }

                if (number > 0)
                {
                    r += 1;
                }

                return r;
            }

            public static ulong Decode(ulong number)
            {
                ulong n = ulong.MaxValue >> 1;
                ulong d = 1;
                ulong r = 0;
                while (n > 0)
                {
                    if (number >= n)
                    {
                        r += d;
                        number -= n;
                        if (number <= 0)
                        {
                            break;
                        }
                    }

                    d <<= 1;
                    n >>= 1;
                }

                if (number > 0)
                {
                    r += d;
                }

                return r;
            }

            #endregion UInt64

            #region Int64

            public static long Encode(long number)
            {
                return (long)Encode((ulong)number);
            }

            public static long Decode(long number)
            {
                return (long)Decode((ulong)number);
            }

            #endregion Int64

            private static string GetNumberTable(NumberSystem numberSystem)
            {
                string numberTable = null;
                switch (numberSystem)
                {
                    case NumberSystem.N8:
                        numberTable = NumberTable_8;
                        break;
                    case NumberSystem.N10:
                        numberTable = NumberTable_10;
                        break;
                    case NumberSystem.N16:
                        numberTable = NumberTable_16;
                        break;
                    case NumberSystem.N26:
                        numberTable = NumberTable_26;
                        break;
                    case NumberSystem.N36:
                        numberTable = NumberTable_36;
                        break;
                    case NumberSystem.N42:
                        numberTable = NumberTable_42;
                        break;
                    case NumberSystem.N62:
                        numberTable = NumberTable_62;
                        break;
                    case NumberSystem.Base64:
                        numberTable = NumberTable_64;
                        break;
                    case NumberSystem.SafeBase64:
                        numberTable = NumberTableSafe_64;
                        break;
                    case NumberSystem.N68:
                        numberTable = NumberTable_68;
                        break;
                    default:
                        break;
                }

                return numberTable;
            }


        }

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
