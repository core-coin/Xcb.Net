using System;
using System.Collections;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.Nist;
using Org.BouncyCastle.Extended.Asn1.Pkcs;
using Org.BouncyCastle.Extended.Asn1.X9;
using Org.BouncyCastle.Extended.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Agreement
{
	public class ECDHWithKdfBasicAgreement
		: ECDHBasicAgreement
	{
		private readonly string algorithm;
		private readonly IDerivationFunction kdf;

		public ECDHWithKdfBasicAgreement(
			string				algorithm,
			IDerivationFunction	kdf)
		{
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");
			if (kdf == null)
				throw new ArgumentNullException("kdf");

			this.algorithm = algorithm;
			this.kdf = kdf;
		}

		public override BigInteger CalculateAgreement(
			ICipherParameters pubKey)
		{
			// Note that the ec.KeyAgreement class in JCE only uses kdf in one
			// of the engineGenerateSecret methods.

			BigInteger result = base.CalculateAgreement(pubKey);

			int keySize = GeneratorUtilities.GetDefaultKeySize(algorithm);

			DHKdfParameters dhKdfParams = new DHKdfParameters(
				new DerObjectIdentifier(algorithm),
				keySize,
				BigIntToBytes(result));

			kdf.Init(dhKdfParams);

			byte[] keyBytes = new byte[keySize / 8];
			kdf.GenerateBytes(keyBytes, 0, keyBytes.Length);

			return new BigInteger(1, keyBytes);
		}

		private byte[] BigIntToBytes(BigInteger r)
		{
			int byteLength = X9IntegerConverter.GetByteLength(privKey.Parameters.Curve);
			return X9IntegerConverter.IntegerToBytes(r, byteLength);
		}
	}
}
