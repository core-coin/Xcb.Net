using System;
using System.IO;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    public class TlsException
        : IOException
    {
        public TlsException(string message, Exception cause)
            : base(message, cause)
        {
        }
    }
}
