using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.CryptoPro;
using Org.BouncyCastle.Extended.Asn1.Pkcs;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Asn1.X9;
using Org.BouncyCastle.Extended.Crypto;
using Org.BouncyCastle.Extended.Crypto.Generators;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Pkcs;
using Org.BouncyCastle.Extended.Security;
using Org.BouncyCastle.Extended.Security.Certificates;
using Org.BouncyCastle.Extended.Utilities.Encoders;
using Org.BouncyCastle.Extended.Utilities.IO.Pem;
using Org.BouncyCastle.Extended.X509;

namespace Org.BouncyCastle.Extended.OpenSsl
{
	/// <remarks>General purpose writer for OpenSSL PEM objects.</remarks>
	public class PemWriter
		: Org.BouncyCastle.Extended.Utilities.IO.Pem.PemWriter
	{
		/// <param name="writer">The TextWriter object to write the output to.</param>
		public PemWriter(
			TextWriter writer)
			: base(writer)
		{
		}

		public void WriteObject(
			object obj) 
		{
			try
			{
				base.WriteObject(new MiscPemGenerator(obj));
			}
			catch (PemGenerationException e)
			{
				if (e.InnerException is IOException)
					throw (IOException)e.InnerException;

				throw e;
			}
		}

		public void WriteObject(
			object			obj,
			string			algorithm,
			char[]			password,
			SecureRandom	random)
		{
			base.WriteObject(new MiscPemGenerator(obj, algorithm, password, random));
		}
	}
}
