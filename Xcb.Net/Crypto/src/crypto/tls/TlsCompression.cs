using System;
using System.IO;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
	public interface TlsCompression
	{
		Stream Compress(Stream output);

		Stream Decompress(Stream output);
	}
}
