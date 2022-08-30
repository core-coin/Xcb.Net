using System;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
	public interface TlsPskIdentity
	{
		void SkipIdentityHint();

		void NotifyIdentityHint(byte[] psk_identity_hint);

		byte[] GetPskIdentity();

		byte[] GetPsk();
	}
}
