using System;

using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Crypto;

namespace Org.BouncyCastle.Extended.Crmf
{
    public interface IPKMacPrimitivesProvider   
    {
	    IDigest CreateDigest(AlgorithmIdentifier digestAlg);

        IMac CreateMac(AlgorithmIdentifier macAlg);
    }
}
