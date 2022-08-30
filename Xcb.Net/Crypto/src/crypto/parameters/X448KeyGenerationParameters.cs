using System;

using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
    public class X448KeyGenerationParameters
        : KeyGenerationParameters
    {
        public X448KeyGenerationParameters(SecureRandom random)
            : base(random, 448)
        {
        }
    }
}
