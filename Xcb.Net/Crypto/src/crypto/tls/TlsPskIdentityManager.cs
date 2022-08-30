using System;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    public interface TlsPskIdentityManager
    {
        byte[] GetHint();

        byte[] GetPsk(byte[] identity);
    }
}
