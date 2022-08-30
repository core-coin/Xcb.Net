using System;

namespace Org.BouncyCastle.Extended.Math.Field
{
    public interface IFiniteField
    {
        BigInteger Characteristic { get; }

        int Dimension { get; }
    }
}
