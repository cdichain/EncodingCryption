using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;


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

            public static byte[] EncryptWithPrivateKey(string pemOrXmlPrivateKey, string plaintext)
            {
                if (pemOrXmlPrivateKey.TrimStart().StartsWith("<"))
                {
                    return UseXmlPrivateKey(pemOrXmlPrivateKey).Encrypt(plaintext);
                }

                return UsePemPrivateKey(pemOrXmlPrivateKey).Encrypt(plaintext);
            }

            public static string DecryptWithPublicKey(string pemOrXmlPublicKey, string ciphertext)
            {
                if (pemOrXmlPublicKey.TrimStart().StartsWith("<"))
                {
                    return UseXmlPublicaKey(pemOrXmlPublicKey).Decrypt(ciphertext);
                }

                return UsePemPublicKey(pemOrXmlPublicKey).Decrypt(ciphertext);
            }

            public static KeyPair CreateKeyPair()
            {
                var rsa = new RSACryptoServiceProvider();
                return new KeyPair
                {
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

            public static AsymmetricCipherKeyPair GetRsaKeyPair(RSAParameters rp)
            {
                BigInteger modulus = new BigInteger(1, rp.Modulus);
                BigInteger pubExp = new BigInteger(1, rp.Exponent);

                RsaKeyParameters pubKey = new RsaKeyParameters(
                    false,
                    modulus,
                    pubExp);

                RsaPrivateCrtKeyParameters privKey = new RsaPrivateCrtKeyParameters(
                    modulus,
                    pubExp,
                    new BigInteger(1, rp.D),
                    new BigInteger(1, rp.P),
                    new BigInteger(1, rp.Q),
                    new BigInteger(1, rp.DP),
                    new BigInteger(1, rp.DQ),
                    new BigInteger(1, rp.InverseQ));

                return new AsymmetricCipherKeyPair(pubKey, privKey);
            }

            public static AsymmetricCipherKeyPair GetRsaKeyPair(RSACryptoServiceProvider key)
            {
                return GetRsaKeyPair(key.ExportParameters(true));
            }

            public static RsaKeyParameters GetRsaPublicKey(RSAParameters rp)
            {
                return new RsaKeyParameters(
                    false,
                    new BigInteger(1, rp.Modulus),
                    new BigInteger(1, rp.Exponent));
            }

            public static class RsaKeyConvert
            {
                /// <summary>
                /// Public Key Convert pem->xml
                /// </summary>
                /// <param name="publicKey"></param>
                /// <returns></returns>
                public static string PublicKeyPemToXml(string publicKey)
                {
                    publicKey = RsaPemFormatHelper.PublicKeyFormat(publicKey);

                    PemReader pr = new PemReader(new StringReader(publicKey));
                    var obj = pr.ReadObject();
                    if (!(obj is RsaKeyParameters rsaKey))
                    {
                        throw new Exception("Public key format is incorrect");
                    }

                    XElement publicElement = new XElement("RSAKeyValue");
                    //Modulus
                    XElement pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsaKey.Modulus.ToByteArrayUnsigned()));
                    //Exponent
                    XElement pubexponent = new XElement("Exponent", Convert.ToBase64String(rsaKey.Exponent.ToByteArrayUnsigned()));

                    publicElement.Add(pubmodulus);
                    publicElement.Add(pubexponent);
                    return publicElement.ToString();
                }

                /// <summary>
                /// Public Key Convert xml->pem
                /// </summary>
                /// <param name="publicKey"></param>
                /// <returns></returns>
                public static string PublicKeyXmlToPem(string publicKey)
                {
                    XElement root = XElement.Parse(publicKey);
                    //Modulus
                    var modulus = root.Element("Modulus");
                    //Exponent
                    var exponent = root.Element("Exponent");

                    RsaKeyParameters rsaKeyParameters = new RsaKeyParameters(false, new BigInteger(1, Convert.FromBase64String(modulus.Value)), new BigInteger(1, Convert.FromBase64String(exponent.Value)));

                    StringWriter sw = new StringWriter();
                    PemWriter pWrt = new PemWriter(sw);
                    pWrt.WriteObject(rsaKeyParameters);
                    pWrt.Writer.Close();
                    return sw.ToString();
                }

                /// <summary>
                /// Private Key Convert Pkcs1->xml
                /// </summary>
                /// <param name="privateKey"></param>
                /// <returns></returns>
                public static string PrivateKeyPkcs1ToXml(string privateKey)
                {
                    privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);

                    PemReader pr = new PemReader(new StringReader(privateKey));
                    if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
                    {
                        throw new Exception("Private key format is incorrect");
                    }
                    RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters =
                        (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(
                            PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));

                    XElement privatElement = new XElement("RSAKeyValue");
                    //Modulus
                    XElement primodulus = new XElement("Modulus", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned()));
                    //Exponent
                    XElement priexponent = new XElement("Exponent", Convert.ToBase64String(rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned()));
                    //P
                    XElement prip = new XElement("P", Convert.ToBase64String(rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned()));
                    //Q
                    XElement priq = new XElement("Q", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned()));
                    //DP
                    XElement pridp = new XElement("DP", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned()));
                    //DQ
                    XElement pridq = new XElement("DQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned()));
                    //InverseQ
                    XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned()));
                    //D
                    XElement prid = new XElement("D", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()));

                    privatElement.Add(primodulus);
                    privatElement.Add(priexponent);
                    privatElement.Add(prip);
                    privatElement.Add(priq);
                    privatElement.Add(pridp);
                    privatElement.Add(pridq);
                    privatElement.Add(priinverseQ);
                    privatElement.Add(prid);

                    return privatElement.ToString();
                }

                /// <summary>
                /// Private Key Convert xml->Pkcs1
                /// </summary>
                /// <param name="privateKey"></param>
                /// <returns></returns>
                public static string PrivateKeyXmlToPkcs1(string privateKey)
                {
                    XElement root = XElement.Parse(privateKey);
                    //Modulus
                    var modulus = root.Element("Modulus");
                    //Exponent
                    var exponent = root.Element("Exponent");
                    //P
                    var p = root.Element("P");
                    //Q
                    var q = root.Element("Q");
                    //DP
                    var dp = root.Element("DP");
                    //DQ
                    var dq = root.Element("DQ");
                    //InverseQ
                    var inverseQ = root.Element("InverseQ");
                    //D
                    var d = root.Element("D");

                    RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                        new BigInteger(1, Convert.FromBase64String(modulus.Value)),
                        new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                        new BigInteger(1, Convert.FromBase64String(d.Value)),
                        new BigInteger(1, Convert.FromBase64String(p.Value)),
                        new BigInteger(1, Convert.FromBase64String(q.Value)),
                        new BigInteger(1, Convert.FromBase64String(dp.Value)),
                        new BigInteger(1, Convert.FromBase64String(dq.Value)),
                        new BigInteger(1, Convert.FromBase64String(inverseQ.Value)));

                    StringWriter sw = new StringWriter();
                    PemWriter pWrt = new PemWriter(sw);
                    pWrt.WriteObject(rsaPrivateCrtKeyParameters);
                    pWrt.Writer.Close();
                    return sw.ToString();

                }


                /// <summary>
                /// Private Key Convert Pkcs8->xml
                /// </summary>
                /// <param name="privateKey"></param>
                /// <returns></returns>
                public static string PrivateKeyPkcs8ToXml(string privateKey)
                {
                    privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);
                    RsaPrivateCrtKeyParameters privateKeyParam =
                        (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

                    XElement privatElement = new XElement("RSAKeyValue");
                    //Modulus
                    XElement primodulus = new XElement("Modulus", Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()));
                    //Exponent
                    XElement priexponent = new XElement("Exponent", Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()));
                    //P
                    XElement prip = new XElement("P", Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()));
                    //Q
                    XElement priq = new XElement("Q", Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()));
                    //DP
                    XElement pridp = new XElement("DP", Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()));
                    //DQ
                    XElement pridq = new XElement("DQ", Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()));
                    //InverseQ
                    XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()));
                    //D
                    XElement prid = new XElement("D", Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));

                    privatElement.Add(primodulus);
                    privatElement.Add(priexponent);
                    privatElement.Add(prip);
                    privatElement.Add(priq);
                    privatElement.Add(pridp);
                    privatElement.Add(pridq);
                    privatElement.Add(priinverseQ);
                    privatElement.Add(prid);

                    return privatElement.ToString();
                }

                /// <summary>
                /// Private Key Convert xml->Pkcs8
                /// </summary>
                /// <param name="privateKey"></param>
                /// <returns></returns>
                public static string PrivateKeyXmlToPkcs8(string privateKey)
                {
                    XElement root = XElement.Parse(privateKey);
                    //Modulus
                    var modulus = root.Element("Modulus");
                    //Exponent
                    var exponent = root.Element("Exponent");
                    //P
                    var p = root.Element("P");
                    //Q
                    var q = root.Element("Q");
                    //DP
                    var dp = root.Element("DP");
                    //DQ
                    var dq = root.Element("DQ");
                    //InverseQ
                    var inverseQ = root.Element("InverseQ");
                    //D
                    var d = root.Element("D");

                    RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                        new BigInteger(1, Convert.FromBase64String(modulus.Value)),
                        new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                        new BigInteger(1, Convert.FromBase64String(d.Value)),
                        new BigInteger(1, Convert.FromBase64String(p.Value)),
                        new BigInteger(1, Convert.FromBase64String(q.Value)),
                        new BigInteger(1, Convert.FromBase64String(dp.Value)),
                        new BigInteger(1, Convert.FromBase64String(dq.Value)),
                        new BigInteger(1, Convert.FromBase64String(inverseQ.Value)));

                    StringWriter swpri = new StringWriter();
                    PemWriter pWrtpri = new PemWriter(swpri);
                    Pkcs8Generator pkcs8 = new Pkcs8Generator(rsaPrivateCrtKeyParameters);
                    pWrtpri.WriteObject(pkcs8);
                    pWrtpri.Writer.Close();
                    return swpri.ToString();

                }

                /// <summary>
                /// Private Key Convert Pkcs1->Pkcs8
                /// </summary>
                /// <param name="privateKey"></param>
                /// <returns></returns>
                public static string PrivateKeyPkcs1ToPkcs8(string privateKey)
                {
                    privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);
                    PemReader pr = new PemReader(new StringReader(privateKey));

                    AsymmetricCipherKeyPair kp = pr.ReadObject() as AsymmetricCipherKeyPair;
                    StringWriter sw = new StringWriter();
                    PemWriter pWrt = new PemWriter(sw);
                    Pkcs8Generator pkcs8 = new Pkcs8Generator(kp.Private);
                    pWrt.WriteObject(pkcs8);
                    pWrt.Writer.Close();
                    string result = sw.ToString();
                    return result;
                }

                /// <summary>
                /// Private Key Convert Pkcs8->Pkcs1
                /// </summary>
                /// <param name="privateKey"></param>
                /// <returns></returns>
                public static string PrivateKeyPkcs8ToPkcs1(string privateKey)
                {
                    privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormat(privateKey);
                    PemReader pr = new PemReader(new StringReader(privateKey));

                    RsaPrivateCrtKeyParameters kp = pr.ReadObject() as RsaPrivateCrtKeyParameters;

                    var keyParameter = PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp));

                    StringWriter sw = new StringWriter();
                    PemWriter pWrt = new PemWriter(sw);
                    pWrt.WriteObject(keyParameter);
                    pWrt.Writer.Close();
                    string result = sw.ToString();
                    return result;
                }
            }

            public static class RsaPemFormatHelper
            {
                /// <summary>
                /// Format Pkcs1 format private key
                /// Author:Zhiqiang Li
                /// </summary>
                /// <param name="str"></param>
                /// <returns></returns>
                public static string Pkcs1PrivateKeyFormat(string str)
                {
                    if (str.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
                    {
                        return str;
                    }

                    List<string> res = new List<string>();
                    res.Add("-----BEGIN RSA PRIVATE KEY-----");

                    int pos = 0;

                    while (pos < str.Length)
                    {
                        var count = str.Length - pos < 64 ? str.Length - pos : 64;
                        res.Add(str.Substring(pos, count));
                        pos += count;
                    }

                    res.Add("-----END RSA PRIVATE KEY-----");
                    var resStr = string.Join(Environment.NewLine, res);
                    return resStr;
                }

                /// <summary>
                /// Remove the Pkcs1 format private key format
                /// </summary>
                /// <param name="str"></param>
                /// <returns></returns>
                public static string Pkcs1PrivateKeyFormatRemove(string str)
                {
                    if (!str.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
                    {
                        return str;
                    }
                    return str.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "")
                        .Replace(Environment.NewLine, "");
                }

                /// <summary>
                /// Format Pkcs8 format private key
                /// </summary>
                /// <param name="str"></param>
                /// <returns></returns>
                public static string Pkcs8PrivateKeyFormat(string str)
                {
                    if (str.StartsWith("-----BEGIN PRIVATE KEY-----"))
                    {
                        return str;
                    }
                    List<string> res = new List<string>();
                    res.Add("-----BEGIN PRIVATE KEY-----");

                    int pos = 0;

                    while (pos < str.Length)
                    {
                        var count = str.Length - pos < 64 ? str.Length - pos : 64;
                        res.Add(str.Substring(pos, count));
                        pos += count;
                    }

                    res.Add("-----END PRIVATE KEY-----");
                    var resStr = string.Join(Environment.NewLine, res);
                    return resStr;
                }

                /// <summary>
                /// Remove the Pkcs8 format private key format
                /// </summary>
                /// <param name="str"></param>
                /// <returns></returns>
                public static string Pkcs8PrivateKeyFormatRemove(string str)
                {
                    if (!str.StartsWith("-----BEGIN PRIVATE KEY-----"))
                    {
                        return str;
                    }
                    return str.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "")
                        .Replace(Environment.NewLine, "");
                }

                /// <summary>
                /// Format public key
                /// </summary>
                /// <param name="str"></param>
                /// <returns></returns>
                public static string PublicKeyFormat(string str)
                {
                    if (str.StartsWith("-----BEGIN PUBLIC KEY-----"))
                    {
                        return str;
                    }
                    List<string> res = new List<string>();
                    res.Add("-----BEGIN PUBLIC KEY-----");
                    int pos = 0;

                    while (pos < str.Length)
                    {
                        var count = str.Length - pos < 64 ? str.Length - pos : 64;
                        res.Add(str.Substring(pos, count));
                        pos += count;
                    }
                    res.Add("-----END PUBLIC KEY-----");
                    var resStr = string.Join(Environment.NewLine, res);
                    return resStr;
                }

                /// <summary>
                /// Public key format removed
                /// </summary>
                /// <param name="str"></param>
                /// <returns></returns>
                public static string PublicKeyFormatRemove(string str)
                {
                    if (!str.StartsWith("-----BEGIN PUBLIC KEY-----"))
                    {
                        return str;
                    }
                    return str.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "")
                        .Replace(Environment.NewLine, "");
                }
            }
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

            public string Decrypt(string ciphertext)
            {
                //加载公钥
                RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();
                publicRsa.FromXmlString(_xmlPubKey);
                RSAParameters rp = publicRsa.ExportParameters(false);

                //转换密钥
                AsymmetricKeyParameter pbk = RSA.GetRsaPublicKey(rp);

                IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥
                c.Init(false, pbk);

                byte[] DataToDecrypt = Convert.FromBase64String(ciphertext);
                byte[] outBytes = c.DoFinal(DataToDecrypt);//解密

                string strDec = Encoding.UTF8.GetString(outBytes);
                return strDec;
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
            private readonly string _xmlPrivateKey;

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

            public byte[] Encrypt(string plaintext)
            {
                //加载私钥
                RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider();
                privateRsa.FromXmlString(_xmlPrivateKey);

                //转换密钥
                AsymmetricCipherKeyPair keyPair = RSA.GetRsaKeyPair(privateRsa);
                IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding"); //使用RSA/ECB/PKCS1Padding格式
                                                                                       //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥

                c.Init(true, keyPair.Private);
                byte[] DataToEncrypt = Encoding.UTF8.GetBytes(plaintext);

                return c.DoFinal(DataToEncrypt);//加密
            }
        }
    }
}
