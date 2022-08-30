using System;

namespace Org.BouncyCastle.Extended.Math.Field
{
    public interface IPolynomial
    {
        int Degree { get; }

        //BigInteger[] GetCoefficients();

        int[] GetExponentsPresent();

        //Term[] GetNonZeroTerms();
    }
}
