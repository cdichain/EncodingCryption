using CDiChain.EncodingCryption.Encoder;
using CDiChain.EncodingCryption.SMCryption;
using System;
using System.Text;

namespace CDiChain.EncodingCryption
{
    public partial class CryptionAlgorithm
    {
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

            public static string Decrypt_ECB(string ciphertext, byte[] password, Encoding encoding = null)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                var model =EncodingExtension. IsHexString(ciphertext) ? EncryptionResultTypes.HexString : EncryptionResultTypes.Base64String;
                var sm4 = new SM4Algorithm(password, null, encoding, model);

                return sm4.DecryptString(ciphertext, SM4Models.ECB);
            }

            public static string Decrypt_CBC(string ciphertext, byte[] password, byte[] iv, Encoding encoding = null)
            {
                if (encoding == null)
                {
                    encoding = Encoding.UTF8;
                }

                var model = EncodingExtension.IsHexString(ciphertext) ? EncryptionResultTypes.HexString : EncryptionResultTypes.Base64String;
                var sm4 = new SM4Algorithm(password, iv, encoding, model);

                return sm4.DecryptString(ciphertext, SM4Models.CBC);
            }
        }
    }
}
