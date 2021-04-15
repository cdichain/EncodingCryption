using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CDiChain.EncodingCryption.SMCryption.SM2.Lib;

namespace CDiChain.EncodingCryption
{
    public partial class CryptionAlgorithm
    {
        public static class SM2
        {
            public static string Encrypt(byte[] publicKey, byte[] data, SM2CombinMode combinMode)
            {
                return SM2Utils.Encrypt(publicKey, data, combinMode);
            }


            //public static X509Certificate2 GetCertificateFromBytes(byte[] cert)
            //{
            //    string certFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            //    try
            //    {
            //        File.WriteAllBytes(certFile, cert);

            //        X509Store store = new X509Store(StoreLocation.CurrentUser);
            //        try
            //        {
            //            store.Open(OpenFlags.ReadOnly);
            //            X509Certificate2Collection certCollection = store.Certificates;
            //            return certCollection[0];
            //        }
            //        finally
            //        {
            //            store.Close();
            //        }
            //    }
            //    finally
            //    {
            //        File.Delete(certFile);
            //    }
            //}
        }
    }
}
