using System;
using System.IO;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    public interface TlsAgreementCredentials
        :   TlsCredentials
    {
        /// <exception cref="IOException"></exception>
        byte[] GenerateAgreement(AsymmetricKeyParameter peerPublicKey);
    }
}
