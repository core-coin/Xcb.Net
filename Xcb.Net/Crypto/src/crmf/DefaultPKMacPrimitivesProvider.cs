using System;

using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Crypto;
using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crmf
{
    public class DefaultPKMacPrimitivesProvider
        : IPKMacPrimitivesProvider
    {
        public IDigest CreateDigest(AlgorithmIdentifier digestAlg)
        {
            return DigestUtilities.GetDigest(digestAlg.Algorithm);
        }

        public IMac CreateMac(AlgorithmIdentifier macAlg)
        {
            return MacUtilities.GetMac(macAlg.Algorithm);
        }
    }
}
