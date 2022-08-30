using System;

using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Generators
{
    public class X448KeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom random;

        public virtual void Init(KeyGenerationParameters parameters)
        {
            this.random = parameters.Random;
        }

        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            X448PrivateKeyParameters privateKey = new X448PrivateKeyParameters(random);
            X448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
