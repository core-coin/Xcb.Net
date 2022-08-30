using System;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
	public interface TlsCredentials
	{
		Certificate Certificate { get; }
	}
}
