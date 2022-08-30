using System;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    public abstract class AbstractTlsCredentials
        :   TlsCredentials
    {
        public abstract Certificate Certificate { get; }
    }
}
