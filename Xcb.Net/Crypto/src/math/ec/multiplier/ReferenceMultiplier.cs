using System;

namespace Org.BouncyCastle.Extended.Math.EC.Multiplier
{
    [Obsolete("Will be removed")]
    public class ReferenceMultiplier
        : AbstractECMultiplier
    {
        protected override ECPoint MultiplyPositive(ECPoint p, BigInteger k)
        {
            return ECAlgorithms.ReferenceMultiply(p, k);
        }
    }
}
