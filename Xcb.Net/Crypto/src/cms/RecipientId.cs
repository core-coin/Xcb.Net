using System;

using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Utilities;
using Org.BouncyCastle.Extended.X509.Store;

namespace Org.BouncyCastle.Extended.Cms
{
    public class RecipientID
        : X509CertStoreSelector
    {
        private byte[] keyIdentifier;

		public byte[] KeyIdentifier
		{
			get { return Arrays.Clone(keyIdentifier); }
			set { keyIdentifier = Arrays.Clone(value); }
		}

		public override int GetHashCode()
        {
            int code = Arrays.GetHashCode(keyIdentifier)
				^ Arrays.GetHashCode(this.SubjectKeyIdentifier);

			BigInteger serialNumber = this.SerialNumber;
			if (serialNumber != null)
            {
                code ^= serialNumber.GetHashCode();
            }

			X509Name issuer = this.Issuer;
            if (issuer != null)
            {
                code ^= issuer.GetHashCode();
            }

            return code;
        }

        public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			RecipientID id = obj as RecipientID;

			if (id == null)
				return false;

			return Arrays.AreEqual(keyIdentifier, id.keyIdentifier)
				&& Arrays.AreEqual(SubjectKeyIdentifier, id.SubjectKeyIdentifier)
				&& Platform.Equals(SerialNumber, id.SerialNumber)
				&& IssuersMatch(Issuer, id.Issuer);
        }
    }
}
