using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.Ocsp;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.X509;

namespace Org.BouncyCastle.Extended.Ocsp
{
	public class Req
		: X509ExtensionBase
	{
		private Request req;

		public Req(
			Request req)
		{
			this.req = req;
		}

		public CertificateID GetCertID()
		{
			return new CertificateID(req.ReqCert);
		}

		public X509Extensions SingleRequestExtensions
		{
			get { return req.SingleRequestExtensions; }
		}

		protected override X509Extensions GetX509Extensions()
		{
			return SingleRequestExtensions;
		}
	}
}
