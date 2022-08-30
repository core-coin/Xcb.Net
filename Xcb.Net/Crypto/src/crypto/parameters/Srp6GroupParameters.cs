using System;

using Org.BouncyCastle.Extended.Math;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
    public sealed class Srp6GroupParameters
    {
        private readonly BigInteger n, g;

        public Srp6GroupParameters(BigInteger N, BigInteger g)
        {
            this.n = N;
            this.g = g;
        }

        public BigInteger G
        {
            get { return g; }
        }

        public BigInteger N
        {
            get { return n; }
        }
    }
}
