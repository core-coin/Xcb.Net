using System;
using System.IO;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Crypto;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Security;
using Org.BouncyCastle.Extended.Utilities.Date;
using Org.BouncyCastle.Extended.Utilities.IO;

namespace Org.BouncyCastle.Extended.Cms
{
	public class CmsAuthenticatedGenerator
		: CmsEnvelopedGenerator
	{
		/**
		* base constructor
		*/
		public CmsAuthenticatedGenerator()
		{
		}

		/**
		* constructor allowing specific source of randomness
		*
		* @param rand instance of SecureRandom to use
		*/
		public CmsAuthenticatedGenerator(
			SecureRandom rand)
			: base(rand)
		{
		}
	}
}
