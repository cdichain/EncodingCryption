using CDiChain.EncodingCryption.Encoder;
using System;
using System.Text;

namespace CDiChain.EncodingCryption.SMCryption
{
    public class SM3Algorithm : GeneralDigest
    {
        private readonly Encoding _encoding;
        public SM3Algorithm(Encoding encoding)
        {
            Reset();
            _encoding = encoding;
        }

        public SM3Algorithm(SM3Algorithm t)
            : base(t)
        {
            Array.Copy(t.X, 0, X, 0, t.X.Length);
            xOff = t.xOff;
            Array.Copy(t.v, 0, v, 0, t.v.Length);
            _encoding = t._encoding;
        }

        public string Hash(string plaintext)
        {
            var md = new byte[32];
            var msg1 = _encoding.GetBytes(plaintext);
            BlockUpdate(msg1, 0, msg1.Length);
            DoFinal(md, 0);

            return _encoding.GetString(Hex.Encode(md));
        }

        public override string AlgorithmName
        {
            get
            {
                return "SM3";
            }

        }

        public override int GetDigestSize()
        {
            return DIGEST_LENGTH;
        }

        private const int DIGEST_LENGTH = 32;

        private static readonly int[] v0 = new int[] { 0x7380166f, 0x4914b2b9, 0x172442d7, unchecked((int)0xda8a0600), unchecked((int)0xa96f30bc), 0x163138aa, unchecked((int)0xe38dee4d), unchecked((int)0xb0fb0e4e) };

        private int[] v = new int[8];
        private int[] v_ = new int[8];

        private static readonly int[] X0 = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        private int[] X = new int[68];
        private int xOff;

        private int T_00_15 = 0x79cc4519;
        private int T_16_63 = 0x7a879d8a;



        public override void Reset()
        {
            base.Reset();

            Array.Copy(v0, 0, v, 0, v0.Length);

            xOff = 0;
            Array.Copy(X0, 0, X, 0, X0.Length);
        }

        internal override void ProcessBlock()
        {
            int i;

            int[] ww = X;
            int[] ww_ = new int[64];

            for (i = 16; i < 68; i++)
            {
                ww[i] = P1(ww[i - 16] ^ ww[i - 9] ^ (ROTATE(ww[i - 3], 15))) ^ (ROTATE(ww[i - 13], 7)) ^ ww[i - 6];
            }

            for (i = 0; i < 64; i++)
            {
                ww_[i] = ww[i] ^ ww[i + 4];
            }

            int[] vv = v;
            int[] vv_ = v_;

            Array.Copy(vv, 0, vv_, 0, v0.Length);

            int SS1, SS2, TT1, TT2, aaa;
            for (i = 0; i < 16; i++)
            {
                aaa = ROTATE(vv_[0], 12);
                SS1 = aaa + vv_[4] + ROTATE(T_00_15, i);
                SS1 = ROTATE(SS1, 7);
                SS2 = SS1 ^ aaa;

                TT1 = FF_00_15(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
                TT2 = GG_00_15(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
                vv_[3] = vv_[2];
                vv_[2] = ROTATE(vv_[1], 9);
                vv_[1] = vv_[0];
                vv_[0] = TT1;
                vv_[7] = vv_[6];
                vv_[6] = ROTATE(vv_[5], 19);
                vv_[5] = vv_[4];
                vv_[4] = P0(TT2);
            }
            for (i = 16; i < 64; i++)
            {
                aaa = ROTATE(vv_[0], 12);
                SS1 = aaa + vv_[4] + ROTATE(T_16_63, i);
                SS1 = ROTATE(SS1, 7);
                SS2 = SS1 ^ aaa;

                TT1 = FF_16_63(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
                TT2 = GG_16_63(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
                vv_[3] = vv_[2];
                vv_[2] = ROTATE(vv_[1], 9);
                vv_[1] = vv_[0];
                vv_[0] = TT1;
                vv_[7] = vv_[6];
                vv_[6] = ROTATE(vv_[5], 19);
                vv_[5] = vv_[4];
                vv_[4] = P0(TT2);
            }
            for (i = 0; i < 8; i++)
            {
                vv[i] ^= vv_[i];
            }

            // Reset
            xOff = 0;
            Array.Copy(X0, 0, X, 0, X0.Length);
        }

        internal override void ProcessWord(byte[] in_Renamed, int inOff)
        {
            int n = in_Renamed[inOff] << 24;
            n |= (in_Renamed[++inOff] & 0xff) << 16;
            n |= (in_Renamed[++inOff] & 0xff) << 8;
            n |= (in_Renamed[++inOff] & 0xff);
            X[xOff] = n;

            if (++xOff == 16)
            {
                ProcessBlock();
            }
        }

        internal override void ProcessLength(long bitLength)
        {
            if (xOff > 14)
            {
                ProcessBlock();
            }

            X[14] = (int)URShift(bitLength, 32);
            X[15] = (int)(bitLength & unchecked((int)0xffffffff));
        }

        public static void IntToBigEndian(int n, byte[] bs, int off)
        {
            bs[off] = (byte)(URShift(n, 24));
            bs[++off] = (byte)(URShift(n, 16));
            bs[++off] = (byte)(URShift(n, 8));
            bs[++off] = (byte)(n);
        }

        public override int DoFinal(byte[] out_Renamed, int outOff)
        {
            Finish();

            for (int i = 0; i < 8; i++)
            {
                IntToBigEndian(v[i], out_Renamed, outOff + i * 4);
            }

            Reset();

            return DIGEST_LENGTH;
        }

        private int ROTATE(int x, int n)
        {
            return (x << n) | (URShift(x, (32 - n)));
        }

        private int P0(int X)
        {
            return ((X) ^ ROTATE((X), 9) ^ ROTATE((X), 17));
        }

        private int P1(int X)
        {
            return ((X) ^ ROTATE((X), 15) ^ ROTATE((X), 23));
        }

        private int FF_00_15(int X, int Y, int Z)
        {
            return (X ^ Y ^ Z);
        }

        private int FF_16_63(int X, int Y, int Z)
        {
            return ((X & Y) | (X & Z) | (Y & Z));
        }

        private int GG_00_15(int X, int Y, int Z)
        {
            return (X ^ Y ^ Z);
        }

        private int GG_16_63(int X, int Y, int Z)
        {
            return ((X & Y) | (~X & Z));
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        ///<param name="number">Number to operate on
        ///<param name="bits">Ammount of bits to shift
        /// <returns>The resulting number from the shift operation</returns>
        private static int URShift(int number, int bits)
        {
            return number >= 0 ? number >> bits : (number >> bits) + (2 << ~bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        ///<param name="number">Number to operate on
        ///<param name="bits">Ammount of bits to shift
        /// <returns>The resulting number from the shift operation</returns>
        private static int URShift(int number, long bits)
        {
            return URShift(number, (int)bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        ///<param name="number">Number to operate on
        ///<param name="bits">Ammount of bits to shift
        /// <returns>The resulting number from the shift operation</returns>
        private static long URShift(long number, int bits)
        {
            return number >= 0 ? number >> bits : (number >> bits) + (2L << ~bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        ///<param name="number">Number to operate on
        ///<param name="bits">Ammount of bits to shift
        /// <returns>The resulting number from the shift operation</returns>
        private static long URShift(long number, long bits)
        {
            return URShift(number, (int)bits);
        }
    }
}
