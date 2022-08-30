using System;

using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Crypto.Parameters;

namespace Org.BouncyCastle.Extended.Cms
{
	internal interface CmsSecureReadable
	{
		AlgorithmIdentifier Algorithm { get; }
		object CryptoObject { get; }
		CmsReadable GetReadable(KeyParameter key);
	}
}
