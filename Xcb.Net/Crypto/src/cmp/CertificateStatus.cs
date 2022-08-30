using System;

using Org.BouncyCastle.Extended.Asn1.Cmp;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Cms;
using Org.BouncyCastle.Extended.Crypto.IO;
using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Security;
using Org.BouncyCastle.Extended.Utilities;
using Org.BouncyCastle.Extended.X509;

namespace Org.BouncyCastle.Extended.Cmp
{
    public class CertificateStatus
    {
        private static readonly DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();

        private readonly DefaultDigestAlgorithmIdentifierFinder digestAlgFinder;
        private readonly CertStatus certStatus;

        public CertificateStatus(DefaultDigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus)
        {
            this.digestAlgFinder = digestAlgFinder;
            this.certStatus = certStatus;
        }

        public PkiStatusInfo PkiStatusInfo
        {
            get { return certStatus.StatusInfo; }
        }

        public BigInteger CertRequestId
        {
            get { return certStatus.CertReqID.Value; }
        }

        public bool IsVerified(X509Certificate cert)
        {
            AlgorithmIdentifier digAlg = digestAlgFinder.find(sigAlgFinder.Find(cert.SigAlgName));
            if (null == digAlg)
                throw new CmpException("cannot find algorithm for digest from signature " + cert.SigAlgName);

            byte[] digest = DigestUtilities.CalculateDigest(digAlg.Algorithm, cert.GetEncoded());

            return Arrays.ConstantTimeAreEqual(certStatus.CertHash.GetOctets(), digest);
        }
    }
}
