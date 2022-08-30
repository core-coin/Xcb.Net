using System;

using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
    public class Ed448KeyGenerationParameters
        : KeyGenerationParameters
    {
        public Ed448KeyGenerationParameters(SecureRandom random)
            : base(random, 448)
        {
        }
    }
}
