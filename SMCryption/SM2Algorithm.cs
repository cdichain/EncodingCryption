using CDiChain.EncodingCryption.Encoder;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace CDiChain.EncodingCryption.SMCryption
{
    public class SM2Algorithm
    {
        public static readonly string[] sm2_param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// gx,4
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" // gy,5
        };

        public string[] ecc_param = sm2_param;

        public readonly BigInteger ecc_p;
        public readonly BigInteger ecc_a;
        public readonly BigInteger ecc_b;
        public readonly BigInteger ecc_n;
        public readonly BigInteger ecc_gx;
        public readonly BigInteger ecc_gy;

        public readonly ECCurve ecc_curve;
        public readonly ECPoint ecc_point_g;

        public readonly ECDomainParameters ecc_bc_spec;

        public readonly ECKeyPairGenerator ecc_key_pair_generator;

        private byte keyOff;

        public SM2Algorithm()
        {
            ecc_param = sm2_param;

            ECFieldElement ecc_gx_fieldelement;
            ECFieldElement ecc_gy_fieldelement;

            ecc_p = new BigInteger(ecc_param[0], 16);
            ecc_a = new BigInteger(ecc_param[1], 16);
            ecc_b = new BigInteger(ecc_param[2], 16);
            ecc_n = new BigInteger(ecc_param[3], 16);
            ecc_gx = new BigInteger(ecc_param[4], 16);
            ecc_gy = new BigInteger(ecc_param[5], 16);


            ecc_gx_fieldelement = new FpFieldElement(ecc_p, ecc_gx);
            ecc_gy_fieldelement = new FpFieldElement(ecc_p, ecc_gy);

            ecc_curve = new FpCurve(ecc_p, ecc_a, ecc_b);
            ecc_point_g = new FpPoint(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);

            ecc_bc_spec = new ECDomainParameters(ecc_curve, ecc_point_g, ecc_n);

            ECKeyGenerationParameters ecc_ecgenparam;
            ecc_ecgenparam = new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());

            ecc_key_pair_generator = new ECKeyPairGenerator();
            ecc_key_pair_generator.Init(ecc_ecgenparam);
        }

        public virtual byte[] Sm2GetZ(byte[] userId, ECPoint userKey)
        {
            SM3Digest sm3 = new SM3Digest();
            byte[] p;
            // userId length
            int len = userId.Length * 8;
            sm3.Update((byte)(len >> 8 & 0x00ff));
            sm3.Update((byte)(len & 0x00ff));

            // userId
            sm3.BlockUpdate(userId, 0, userId.Length);

            // a,b
            p = ecc_a.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_b.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            // gx,gy
            p = ecc_gx.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_gy.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // x,y
            p = userKey.AffineXCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = userKey.AffineYCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // Z
            byte[] md = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(md, 0);

            return md;
        }

        public void GenerateKeyPair(out ECPoint pubk, out BigInteger prik)
        {
            AsymmetricCipherKeyPair key = ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;

            //System.Console.Out.WriteLine("公钥: " + Encoding.ASCII.GetString(Hex.Encode(publicKey.GetEncoded())).ToUpper());
            //System.Console.Out.WriteLine("私钥: " + Encoding.ASCII.GetString(Hex.Encode(privateKey.ToByteArray())).ToUpper());
            pubk = publicKey;
            prik = privateKey;
        }

        public string Encrypt(byte[] publicKey, byte[] data)
        {
            if (null == publicKey || publicKey.Length == 0)
            {
                return null;
            }
            if (data == null || data.Length == 0)
            {
                return null;
            }

            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);
            ECPoint userKey = ecc_curve.DecodePoint(publicKey);

            AsymmetricCipherKeyPair key = ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger k = ecpriv.D;
            ECPoint c1 = ecpub.Q;
            var p2 = userKey.Multiply(k);
            var sm3keybase = new SM3Digest();
            var sm3c3 = new SM3Digest();

            byte[] p = byteConvert32Bytes(p2.Normalize().XCoord.ToBigInteger());
            sm3keybase.BlockUpdate(p, 0, p.Length);
            sm3c3.BlockUpdate(p, 0, p.Length);
            p = byteConvert32Bytes(p2.Normalize().YCoord.ToBigInteger());
            sm3keybase.BlockUpdate(p, 0, p.Length);
            var ct = 1;
            var outKey = NextKey(sm3keybase, ct);
            sm3c3.BlockUpdate(data, 0, data.Length);
            keyOff = 0;
            for (int i = 0; i < data.Length; i++)
            {
                if (keyOff == outKey.Length)
                {
                    ct++;
                    NextKey(sm3keybase, ct);
                }
                data[i] ^= outKey[keyOff++];
            }

            byte[] c3 = new byte[32];
            byte[] p3 = byteConvert32Bytes(p2.Normalize().YCoord.ToBigInteger());
            sm3c3.BlockUpdate(p3, 0, p3.Length);
            sm3c3.DoFinal(c3, 0);

            string sc1 = Encoding.ASCII.GetString(Hex.Encode(c1.GetEncoded()));
            string sc2 = Encoding.ASCII.GetString(Hex.Encode(source));
            string sc3 = Encoding.ASCII.GetString(Hex.Encode(c3));

            return (sc1 + sc2 + sc3).ToUpper();
        }

        private byte[] NextKey(SM3Digest sm3keybase, int ct)
        {
            var key = new byte[32];
            SM3Digest sm3keycur = new SM3Digest(sm3keybase);
            sm3keycur.Update((byte)(ct >> 24 & 0xff));
            sm3keycur.Update((byte)(ct >> 16 & 0xff));
            sm3keycur.Update((byte)(ct >> 8 & 0xff));
            sm3keycur.Update((byte)(ct & 0xff));
            sm3keycur.DoFinal(key, 0);
            this.keyOff = 0;
            return key;
        }

        //public byte[] Decrypt(byte[] privateKey, byte[] encryptedData)
        //{
        //    if (null == privateKey || privateKey.Length == 0)
        //    {
        //        return null;
        //    }
        //    if (encryptedData == null || encryptedData.Length == 0)
        //    {
        //        return null;
        //    }

        //    String data = Encoding.ASCII.GetString(Hex.Encode(encryptedData));

        //    byte[] c1Bytes = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(0, 130)));
        //    int c2Len = encryptedData.Length - 97;
        //    byte[] c2 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130, 2 * c2Len)));
        //    byte[] c3 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130 + 2 * c2Len, 64)));

        //    BigInteger userD = new BigInteger(1, privateKey);

        //    //ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);

        //    ECPoint c1 = ecc_curve.DecodePoint(c1Bytes);
        //    Cipher cipher = new Cipher();
        //    cipher.Init_dec(userD, c1);
        //    cipher.Decrypt(c2);
        //    cipher.Dofinal(c3);

        //    return c2;
        //}

        public static byte[] byteConvert32Bytes(BigInteger n)
        {
            byte[] tmpd = null;
            if (n == null)
            {
                return null;
            }

            if (n.ToByteArray().Length == 33)
            {
                tmpd = new byte[32];
                Array.Copy(n.ToByteArray(), 1, tmpd, 0, 32);
            }
            else if (n.ToByteArray().Length == 32)
            {
                tmpd = n.ToByteArray();
            }
            else
            {
                tmpd = new byte[32];
                for (int i = 0; i < 32 - n.ToByteArray().Length; i++)
                {
                    tmpd[i] = 0;
                }
                Array.Copy(n.ToByteArray(), 0, tmpd, 32 - n.ToByteArray().Length, n.ToByteArray().Length);
            }
            return tmpd;
        }

    }
}
