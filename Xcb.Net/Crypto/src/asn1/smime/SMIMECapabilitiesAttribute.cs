using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.X509;

namespace Org.BouncyCastle.Extended.Asn1.Smime
{
    public class SmimeCapabilitiesAttribute
        : AttributeX509
    {
        public SmimeCapabilitiesAttribute(
            SmimeCapabilityVector capabilities)
            : base(SmimeAttributes.SmimeCapabilities,
                    new DerSet(new DerSequence(capabilities.ToAsn1EncodableVector())))
        {
        }
    }
}
