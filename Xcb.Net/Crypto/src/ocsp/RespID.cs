using System;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.Ocsp;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Crypto;
using Org.BouncyCastle.Extended.Security;
using Org.BouncyCastle.Extended.X509;

namespace Org.BouncyCastle.Extended.Ocsp
{
	/**
	 * Carrier for a ResponderID.
	 */
	public class RespID
	{
		internal readonly ResponderID id;

		public RespID(
			ResponderID id)
		{
			this.id = id;
		}

		public RespID(
			X509Name name)
		{
	        this.id = new ResponderID(name);
		}

		public RespID(
			AsymmetricKeyParameter publicKey)
		{
			try
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

				byte[] keyHash = DigestUtilities.CalculateDigest("SHA1", info.PublicKeyData.GetBytes());

				this.id = new ResponderID(new DerOctetString(keyHash));
			}
			catch (Exception e)
			{
				throw new OcspException("problem creating ID: " + e, e);
			}
		}

		public ResponderID ToAsn1Object()
		{
			return id;
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			RespID other = obj as RespID;

			if (other == null)
				return false;

			return id.Equals(other.id);
		}

		public override int GetHashCode()
		{
			return id.GetHashCode();
		}
	}
}
