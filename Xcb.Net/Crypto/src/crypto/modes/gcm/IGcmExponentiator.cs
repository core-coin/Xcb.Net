using System;

namespace Org.BouncyCastle.Extended.Crypto.Modes.Gcm
{
	public interface IGcmExponentiator
	{
		void Init(byte[] x);
		void ExponentiateX(long pow, byte[] output);
	}
}
