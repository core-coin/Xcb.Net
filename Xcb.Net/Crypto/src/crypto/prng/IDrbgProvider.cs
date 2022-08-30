using System;

using Org.BouncyCastle.Extended.Crypto.Prng.Drbg;

namespace Org.BouncyCastle.Extended.Crypto.Prng
{
    internal interface IDrbgProvider
    {
        ISP80090Drbg Get(IEntropySource entropySource);
    }
}
