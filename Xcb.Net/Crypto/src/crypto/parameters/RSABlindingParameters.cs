using System;

using Org.BouncyCastle.Extended.Math;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
	public class RsaBlindingParameters
		: ICipherParameters
	{
		private readonly RsaKeyParameters	publicKey;
		private readonly BigInteger			blindingFactor;

		public RsaBlindingParameters(
			RsaKeyParameters	publicKey,
			BigInteger			blindingFactor)
		{
			if (publicKey.IsPrivate)
				throw new ArgumentException("RSA parameters should be for a public key");

			this.publicKey = publicKey;
			this.blindingFactor = blindingFactor;
		}

		public RsaKeyParameters PublicKey
		{
			get { return publicKey; }
		}

		public BigInteger BlindingFactor
		{
			get { return blindingFactor; }
		}
	}
}
