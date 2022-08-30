using System;

using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
    public class Ed25519KeyGenerationParameters
        : KeyGenerationParameters
    {
        public Ed25519KeyGenerationParameters(SecureRandom random)
            : base(random, 256)
        {
        }
    }
}
