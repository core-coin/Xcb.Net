using System;

using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Signers
{
    public class RandomDsaKCalculator
        :   IDsaKCalculator
    {
        private BigInteger q;
        private SecureRandom random;

        public virtual bool IsDeterministic
        {
            get { return false; }
        }

        public virtual void Init(BigInteger n, SecureRandom random)
        {
            this.q = n;
            this.random = random;
        }

        public virtual void Init(BigInteger n, BigInteger d, byte[] message)
        {
            throw new InvalidOperationException("Operation not supported");
        }

        public virtual BigInteger NextK()
        {
            int qBitLength = q.BitLength;

            BigInteger k;
            do
            {
                k = new BigInteger(qBitLength, random);
            }
            while (k.SignValue < 1 || k.CompareTo(q) >= 0);

            return k;
        }
    }
}
