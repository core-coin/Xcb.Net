using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Xcb.Net.Extensions;

namespace Xcb.Net.Signer
{
    public class XcbECKey
    {
        private static readonly SecureRandom _secureRandom = new SecureRandom();
        Ed448PrivateKeyParameters _privateKey;

        byte[] _privateKeyBytes = null;
        byte[] _publicKeyBytes = null;

        byte[] _addressBytes = null;

        string _privateKeyHex = null;
        string _publicKeyHex = null;

        string _addressHex = null;

        public XcbECKey(string privateKey) : this(privateKey.HexToByteArray())
        { }

        public XcbECKey(byte[] privateKey)
        {
            _privateKey = new Ed448PrivateKeyParameters(privateKey, 0);
        }

        public byte[] GetPrivateKeyBytes()
        {
            return _privateKeyBytes ?? (_privateKeyBytes = _privateKey.GetEncoded());
        }

        public byte[] GetPublicKeyBytes()
        {
            return _publicKeyBytes ?? (_publicKeyBytes = _privateKey.GeneratePublicKey().GetEncoded());
        }

        public string GetPrivateKeyHex()
        {
            return _privateKeyHex ?? (_privateKeyHex = GetPrivateKeyBytes().ToHex());
        }

        public string GetPublicKeyHex()
        {
            return _publicKeyHex ?? (_publicKeyHex = GetPublicKeyBytes().ToHex());
        }

        // private byte[] GetAddressBytes()
        // {
        //     var pubBytes = GetPublicKeyBytes();

        // }

        private byte[] Sha3Hash(byte[] input){
            var sha3 = SHA3.Net.Sha3.Sha3256();
            var result = sha3.ComputeHash(input);
            return result;
        }

        public static XcbECKey GenerateKey(byte[] seed = null)
        {
            var secureRandom = _secureRandom;
            if (seed != null)
            {
                secureRandom = new SecureRandom();
                secureRandom.SetSeed(seed);
            }

            var gen = new Ed448KeyPairGenerator();
            var keyGenParam = new Ed448KeyGenerationParameters(secureRandom);
            gen.Init(keyGenParam);
            var keyPair = gen.GenerateKeyPair();
            var privateBytes = ((Ed448PrivateKeyParameters)keyPair.Private).GetEncoded();

            return new XcbECKey(privateBytes);
        }
    }
}