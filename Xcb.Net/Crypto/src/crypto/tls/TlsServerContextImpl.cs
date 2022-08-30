using System;

using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    internal class TlsServerContextImpl
        : AbstractTlsContext, TlsServerContext
    {
        internal TlsServerContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters)
            : base(secureRandom, securityParameters)
        {
        }

        public override bool IsServer
        {
            get { return true; }
        }
    }
}
