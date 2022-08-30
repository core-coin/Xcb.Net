using System.IO;

namespace Org.BouncyCastle.Extended.Asn1
{
	public interface Asn1OctetStringParser
		: IAsn1Convertible
	{
		Stream GetOctetStream();
	}
}
