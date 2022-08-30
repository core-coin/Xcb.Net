using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.Pkcs;

namespace Org.BouncyCastle.Extended.Asn1.Smime
{
    public abstract class SmimeAttributes
    {
        public static readonly DerObjectIdentifier SmimeCapabilities = PkcsObjectIdentifiers.Pkcs9AtSmimeCapabilities;
        public static readonly DerObjectIdentifier EncrypKeyPref = PkcsObjectIdentifiers.IdAAEncrypKeyPref;
    }
}
