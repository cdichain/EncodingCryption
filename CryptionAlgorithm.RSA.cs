using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CDiChain.EncodingCryption
{
    public partial class CryptionAlgorithm
    {
        public static class RSA
        {

            public static RsaWithPemPubKey UsePemPublicKey(string pemPubKey) => new RsaWithPemPubKey(pemPubKey);
            public static RsaWithPemPrivateKey UsePemPrivateKey(string pemPrivateKey) => new RsaWithPemPrivateKey(pemPrivateKey);
            public static RsaWithXmlPrivateKey UseXmlPrivateKey(string xmlPrivateKey) => new RsaWithXmlPrivateKey(xmlPrivateKey);
            public static RsaWithXmlPubKey UseXmlPublicaKey(string xmlPublicKey) => new RsaWithXmlPubKey(xmlPublicKey);

            public static byte[] Encrypt(string pemOrXmlPublicKey, string plaintext)
            {
                if (pemOrXmlPublicKey.TrimStart().StartsWith("<"))
                {
                    return UseXmlPublicaKey(pemOrXmlPublicKey).Encrypt(plaintext);
                }

                return UsePemPublicKey(pemOrXmlPublicKey).Encrypt(plaintext);
            }

            public static string Decrypt(string pemOrXmlPrivateKey, string ciphertext)
            {
                if (pemOrXmlPrivateKey.TrimStart().StartsWith("<"))
                {
                    return UseXmlPrivateKey(pemOrXmlPrivateKey).Decrypt(ciphertext);
                }

                return UsePemPrivateKey(pemOrXmlPrivateKey).Decrypt(ciphertext);
            }

            public static KeyPair CreateKeyPair()
            {
                var rsa = new RSACryptoServiceProvider();
                return new KeyPair {
                    PrivateKey = rsa.ToXmlString(true),
                    PublicKey = rsa.ToXmlString(false)
                };
            }

            #region RSA密钥转换
            /// <summary>
            /// C#xml密钥转base64密钥
            /// </summary>
            /// <param name="RSAKey"></param>
            /// <param name="isPrivateKey"></param>
            /// <returns></returns>
            public static string ConvertXmlKeyToPem(string xmlKey, bool isPrivateKey)
            {
                if (string.IsNullOrEmpty(xmlKey))
                {
                    return null;
                }

                string pemKey = string.Empty;
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlKey);
                RSAParameters rsaPara = new RSAParameters();
                RsaKeyParameters key = null;
                if (isPrivateKey)
                {
                    rsaPara = rsa.ExportParameters(true);
                    key = new RsaPrivateCrtKeyParameters(
                            new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent), new BigInteger(1, rsaPara.D),
                            new BigInteger(1, rsaPara.P), new BigInteger(1, rsaPara.Q), new BigInteger(1, rsaPara.DP), new BigInteger(1, rsaPara.DQ),
                            new BigInteger(1, rsaPara.InverseQ));
                }
                else
                {
                    rsaPara = rsa.ExportParameters(false);
                    key = new RsaKeyParameters(false,
                        new BigInteger(1, rsaPara.Modulus),
                        new BigInteger(1, rsaPara.Exponent));
                }

                using (TextWriter sw = new StringWriter())
                {
                    var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
                    pemWriter.WriteObject(key);
                    pemWriter.Writer.Flush();
                    pemKey = sw.ToString();
                }
                return pemKey;
            }
            /// <summary>
            /// base64密钥转xml密钥
            /// </summary>
            /// <param name="pemKey"></param>
            /// <param name="isPrivateKey"></param>
            /// <returns></returns>
            public static string ConvertPemToXmlKey(string pemKey, bool isPrivateKey)
            {
                if (string.IsNullOrEmpty(pemKey))
                {
                    return null;
                }

                string rsaKey = string.Empty;
                object pemObject = null;
                RSAParameters rsaPara = new RSAParameters();
                using (StringReader sReader = new StringReader(pemKey))
                {
                    var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sReader);
                    pemObject = pemReader.ReadObject();
                }
                //RSA私钥
                if (isPrivateKey)
                {
                    //RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)(((AsymmetricCipherKeyPair)pemObject).Private);
                    RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)pemObject;
                    rsaPara = new RSAParameters
                    {
                        Modulus = key.Modulus.ToByteArrayUnsigned(),
                        Exponent = key.PublicExponent.ToByteArrayUnsigned(),
                        D = key.Exponent.ToByteArrayUnsigned(),
                        P = key.P.ToByteArrayUnsigned(),
                        Q = key.Q.ToByteArrayUnsigned(),
                        DP = key.DP.ToByteArrayUnsigned(),
                        DQ = key.DQ.ToByteArrayUnsigned(),
                        InverseQ = key.QInv.ToByteArrayUnsigned(),
                    };
                }
                //RSA公钥
                else
                {
                    RsaKeyParameters key = (RsaKeyParameters)pemObject;
                    rsaPara = new RSAParameters
                    {
                        Modulus = key.Modulus.ToByteArrayUnsigned(),
                        Exponent = key.Exponent.ToByteArrayUnsigned(),
                    };
                }
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaPara);
                using (StringWriter sw = new StringWriter())
                {
                    sw.Write(rsa.ToXmlString(isPrivateKey ? true : false));
                    rsaKey = sw.ToString();
                }
                return rsaKey;
            }
            #endregion

        }


        public class KeyPair
        {
            public string PublicKey { get; set; }

            public string PrivateKey { get; set; }
        }

        public class RsaWithPemPubKey : RsaWithXmlPubKey
        {

            public RsaWithPemPubKey(string pemPubKey)
                : base(CryptionAlgorithm.RSA.ConvertPemToXmlKey(pemPubKey, false))
            {
            }

        }

        public class RsaWithXmlPubKey
        {
            private string _xmlPubKey;

            public RsaWithXmlPubKey(string xmlPubKey)
            {
                _xmlPubKey = xmlPubKey;
            }

            /// <summary>
            /// RSA加密
            /// </summary>
            /// <param name="content">要加密的内容</param>
            /// <returns></returns>
            public byte[] Encrypt(string content)
            {
                string encryptedMsg = string.Empty;
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(_xmlPubKey);
                    return rsa.Encrypt(Encoding.UTF8.GetBytes(content), false);
                }
            }
        }

        public class RsaWithPemPrivateKey : RsaWithXmlPrivateKey
        {

            public RsaWithPemPrivateKey(string pemPrivateKey)
                : base(CryptionAlgorithm.RSA.ConvertPemToXmlKey(pemPrivateKey, true))
            {
            }

        }

        public class RsaWithXmlPrivateKey
        {
            private string _xmlPrivateKey;

            public RsaWithXmlPrivateKey(string xmlPrivateKey)
            {
                _xmlPrivateKey = xmlPrivateKey;
            }

            /// <summary>
            /// RSA解密
            /// </summary>
            /// <param name="content">解密内容</param>
            /// <param name="priKey">私钥（xml格式）</param>
            /// <returns></returns>
            public string Decrypt(string content)
            {
                string decryptedContent = string.Empty;
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(_xmlPrivateKey);
                    var decryptedData = rsa.Decrypt(Convert.FromBase64String(content), false);
                    return Encoding.UTF8.GetString(decryptedData);
                }
            }
        }
    }
}
