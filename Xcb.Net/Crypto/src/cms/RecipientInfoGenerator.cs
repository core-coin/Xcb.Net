using System;

using Org.BouncyCastle.Extended.Asn1.Cms;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Cms
{
	public interface RecipientInfoGenerator
	{
		/// <summary>
		/// Generate a RecipientInfo object for the given key.
		/// </summary>
		/// <param name="contentEncryptionKey">
		/// A <see cref="KeyParameter"/>
		/// </param>
		/// <param name="random">
		/// A <see cref="SecureRandom"/>
		/// </param>
		/// <returns>
		/// A <see cref="RecipientInfo"/>
		/// </returns>
		/// <exception cref="GeneralSecurityException"></exception>
		RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random);
	}
}
