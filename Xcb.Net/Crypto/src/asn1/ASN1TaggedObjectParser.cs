namespace Org.BouncyCastle.Extended.Asn1
{
	public interface Asn1TaggedObjectParser
		: IAsn1Convertible
	{
		int TagNo { get; }

		IAsn1Convertible GetObjectParser(int tag, bool isExplicit);
	}
}
