using System;

using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
    public class X25519KeyGenerationParameters
        : KeyGenerationParameters
    {
        public X25519KeyGenerationParameters(SecureRandom random)
            : base(random, 255)
        {
        }
    }
}
