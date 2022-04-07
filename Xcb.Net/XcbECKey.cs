using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
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
        private static readonly byte[] _defaultNetworkId = new byte[] { 203 };

        private static readonly byte[] _emptyBytes = new byte[] { };
        readonly Ed448PrivateKeyParameters _privateKey;

        byte[] _addressBytes = null;

        string _addressHex = null;

        public int NetworkId { get; }

        public XcbECKey(string privateKey, int networkId) : this(privateKey.HexToByteArray(), networkId)
        { }

        public XcbECKey(byte[] privateKey, int networkId)
        {
            if (privateKey.Length != 57)
                throw new InvalidKeyException("key length must be 57 bytes in length");

            _privateKey = new Ed448PrivateKeyParameters(privateKey, 0);
            NetworkId = networkId;
        }

        public byte[] GetPrivateKey()
        {
            return _privateKey.GetEncoded();
        }

        public byte[] GetPublicKey()
        {
            return _privateKey.GeneratePublicKey().GetEncoded();
        }

        //same as common/types.go:PubkeyToAddress in go-core
        private byte[] GetAddressBytes()
        {
            if (_addressBytes != null)
                return _addressBytes;

            return _addressBytes = GetAddressBytesFromPublicKey(GetPublicKey(), NetworkId);
        }

        public string GetAddress()
        {
            return _addressHex ?? (_addressHex = GetAddressBytes().ToHex());
        }

        /// <summary>
        /// Sign the message directly, give the message bytes to the sign algorithm
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] SignMessage(byte[] message)
        {
            byte[] sign = new byte[Ed448.SignatureSize];
            _privateKey.Sign(Ed448.Algorithm.Ed448, _emptyBytes, message, 0, message.Length, sign, 0);
            var result = sign.ToList();
            result.AddRange(GetPublicKey());
            return result.ToArray();
        }

        /// <summary>
        /// sign hash of the message, first calculate the hash of message, then sign the calculcated hash
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] SignHashOfMessage(byte[] message)
        {
            return SignMessage(Util.Sha3NIST.Current.CalculateHash(message));
        }

        //same as common/types.go:CalculateChecksum in go-core
        private static string CaclulateChecksum(byte[] address, byte[] prefix)
        {
            var concated = new List<byte>(address.Length + prefix.Length);
            concated.AddRange(address);
            concated.AddRange(prefix);

            var addrString = concated.ToArray().ToHex().ToUpper() + "00";
            StringBuilder mods = new StringBuilder(concated.Count);

            foreach (int c in addrString)
            {
                if (c > 64 && c < 91)
                    mods.Append((c - 55).ToString());
                else
                    mods.Append((c - 48).ToString());
            }


            BigInteger bigVal = BigInteger.Parse(mods.ToString());

            BigInteger val97 = new BigInteger(97);
            BigInteger val98 = new BigInteger(98);

            BigInteger remainder = bigVal % val97;
            BigInteger checksum = val98 - remainder;

            var resInt = (int)checksum;

            if (resInt < 10)
                return "0" + resInt.ToString();

            return resInt.ToString();
        }

        public static XcbECKey GenerateKey(int networkId, byte[] seed = null)
        {
            var secureRandom = _secureRandom;
            if (seed != null)
            {
                secureRandom = new SecureRandom(seed);
            }

            var gen = new Ed448KeyPairGenerator();
            var keyGenParam = new Ed448KeyGenerationParameters(secureRandom);
            gen.Init(keyGenParam);
            var keyPair = gen.GenerateKeyPair();
            var privateBytes = ((Ed448PrivateKeyParameters)keyPair.Private).GetEncoded();

            return new XcbECKey(privateBytes, networkId);
        }

        public string GetNeworkIdPrefix()
        {
            return getNetworkIdPrefix(NetworkId);
        }

        private static string getNetworkIdPrefix(int networkId)
        {
            if (networkId == 1)
                return "cb";
            else if (networkId == 3 || networkId == 4)
                return "ab";
            else if (networkId > 10)
                return "ce";
            else
                throw new InvalidOperationException($"network id {networkId} is undefined");
        }

        public static byte[] GetPublicKeyFromSignature(byte[] signature)
        {
            if (signature.Length != 171)
                throw new ArgumentOutOfRangeException("signature must be 171 bytes");

            byte[] publicKey = new byte[57];
            Array.Copy(signature, 114, publicKey, 0, 57);

            return publicKey;
        }

        private static byte[] GetAddressBytesFromPublicKey(byte[] publicKey, int networkId)
        {
            if (publicKey.Length != Ed448.PublicKeySize)
                throw new ArgumentOutOfRangeException($"public key must be {Ed448.PublicKeySize} bytes");

            var pubBytes = publicKey;
            var pubHash = Util.Sha3NIST.Current.CalculateHash(pubBytes);
            var addressBytes = new byte[pubHash.Length - 12];
            var networkIdBytes = getNetworkIdPrefix(networkId).HexToByteArray();

            Array.Copy(pubHash, 12, addressBytes, 0, addressBytes.Length);
            var chsum = CaclulateChecksum(addressBytes, networkIdBytes);
            var chsumBytes = chsum.HexToByteArray();

            var fullAddress = new List<byte>(networkIdBytes.Length + chsumBytes.Length + addressBytes.Length);
            fullAddress.AddRange(networkIdBytes);
            fullAddress.AddRange(chsumBytes);
            fullAddress.AddRange(addressBytes);

            return fullAddress.ToArray();
        }

        public static string GetAddressFromPublicKey(byte[] publicKey, int networkId)
        {
            return GetAddressBytesFromPublicKey(publicKey, networkId).ToHex();
        }
    }
}
