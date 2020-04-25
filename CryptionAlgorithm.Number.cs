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
    }
}
