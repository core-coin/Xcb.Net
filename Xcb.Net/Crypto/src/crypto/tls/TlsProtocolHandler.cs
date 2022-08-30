using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Crypto.Agreement;
using Org.BouncyCastle.Extended.Crypto.Agreement.Srp;
using Org.BouncyCastle.Extended.Crypto.Digests;
using Org.BouncyCastle.Extended.Crypto.Encodings;
using Org.BouncyCastle.Extended.Crypto.Engines;
using Org.BouncyCastle.Extended.Crypto.Generators;
using Org.BouncyCastle.Extended.Crypto.IO;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Crypto.Prng;
using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Security;
using Org.BouncyCastle.Extended.Utilities;
using Org.BouncyCastle.Extended.Utilities.Date;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    [Obsolete("Use 'TlsClientProtocol' instead")]
    public class TlsProtocolHandler
        :   TlsClientProtocol
    {
        public TlsProtocolHandler(Stream stream, SecureRandom secureRandom)
            :   base(stream, stream, secureRandom)
        {
        }

        /// <remarks>Both streams can be the same object</remarks>
        public TlsProtocolHandler(Stream input, Stream output, SecureRandom	secureRandom)
            :   base(input, output, secureRandom)
        {
        }
    }
}
