using System;
using System.Globalization;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Math;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
    public class ECPrivateKeyParameters
        : ECKeyParameters
    {
        private readonly BigInteger d;

        public ECPrivateKeyParameters(
            BigInteger			d,
            ECDomainParameters	parameters)
            : this("EC", d, parameters)
        {
        }

        [Obsolete("Use version with explicit 'algorithm' parameter")]
        public ECPrivateKeyParameters(
            BigInteger			d,
            DerObjectIdentifier publicKeyParamSet)
            : base("ECGOST3410", true, publicKeyParamSet)
        {
            this.d = Parameters.ValidatePrivateScalar(d);
        }

        public ECPrivateKeyParameters(
            string				algorithm,
            BigInteger			d,
            ECDomainParameters	parameters)
            : base(algorithm, true, parameters)
        {
            this.d = Parameters.ValidatePrivateScalar(d);
        }

        public ECPrivateKeyParameters(
            string				algorithm,
            BigInteger			d,
            DerObjectIdentifier publicKeyParamSet)
            : base(algorithm, true, publicKeyParamSet)
        {
            this.d = Parameters.ValidatePrivateScalar(d);
        }

        public BigInteger D
        {
            get { return d; }
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            ECPrivateKeyParameters other = obj as ECPrivateKeyParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        protected bool Equals(
            ECPrivateKeyParameters other)
        {
            return d.Equals(other.d) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return d.GetHashCode() ^ base.GetHashCode();
        }
    }
}
