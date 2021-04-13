using System;
using System.Collections.Generic;
using System.Text;
using static CDiChain.EncodingCryption.SMCryption.SM2Algorithm;

namespace CDiChain.EncodingCryption
{
	public partial class CryptionAlgorithm
	{
		public static class SM2
		{
			public static string Encrypt(byte[] data, byte[] publicKey, SM2CombinMode combinMode)
			{
				var sm2 = new SMCryption.SM2Algorithm(combinMode);
				
				return sm2.Encrypt(publicKey, data);
			}

			public static string Encrypt(byte[] data, string publicKeyBase64, SM2CombinMode combinMode)
			{
				return Encrypt(data, Convert.FromBase64String(publicKeyBase64), combinMode);
			}

			public static string Encrypt(string text, byte[] publicKey, SM2CombinMode combinMode, Encoding encoding = null)
			{
				if (encoding == null)
				{
					encoding = Encoding.UTF8;
				}

				return Encrypt(encoding.GetBytes(text), publicKey, combinMode);
			}

			public static string Encrypt(string text, string publicKeyBase64, SM2CombinMode combinMode, Encoding encoding = null)
			{
				if (encoding == null)
				{
					encoding = Encoding.UTF8;
				}

				return Encrypt(encoding.GetBytes(text), Convert.FromBase64String(publicKeyBase64), combinMode);
			}
		}
	}
}
