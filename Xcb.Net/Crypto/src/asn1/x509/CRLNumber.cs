using Org.BouncyCastle.Extended.Math;

namespace Org.BouncyCastle.Extended.Asn1.X509
{
    /**
     * The CRLNumber object.
     * <pre>
     * CRLNumber::= Integer(0..MAX)
     * </pre>
     */
    public class CrlNumber
        : DerInteger
    {
        public CrlNumber(
			BigInteger number)
			: base(number)
        {
        }

		public BigInteger Number
		{
			get { return PositiveValue; }
		}

		public override string ToString()
		{
			return "CRLNumber: " + Number;
		}
	}
}
