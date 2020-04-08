using System;
using System.Collections.Generic;
using System.Text;

namespace CDiChain.EncodingCryption
{
    public static class NumberExtension
    {
        public static string ToString(this int num, NumberSystem numberSystem, int minimumLength = 1)
        {
            return CryptionAlgorithm.Number.IntToString(num, numberSystem, minimumLength);
        }

        public static int ToInt(this string numStr, NumberSystem numberSystem)
        {
            return CryptionAlgorithm.Number.StringToInt(numStr, numberSystem);
        }

    }
}
