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
        Ed448PrivateKeyParameters _privateKey;

        byte[] _privateKeyBytes = null;
        byte[] _publicKeyBytes = null;

        byte[] _addressBytes = null;

        string _privateKeyHex = null;
        string _publicKeyHex = null;

        string _addressHex = null;

        byte[] _networkId;

        public XcbECKey(string privateKey, string networkId = "cb") : this(privateKey.HexToByteArray(), networkId.HexToByteArray())
        { }

        public XcbECKey(byte[] privateKey, byte[] networkId)
        {
            if(privateKey.Length!=57)
                throw new InvalidKeyException("key length must be 57 bytes");
            _privateKey = new Ed448PrivateKeyParameters(privateKey, 0);
            _networkId = networkId;
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

        //same as common/types.go:PubkeyToAddress in go-core
        public byte[] GetAddressBytes()
        {
            if (_addressBytes != null)
                return _addressBytes;

            var pubBytes = GetPublicKeyBytes();
            var pubHash = Util.Sha3NIST.Current.CalculateHash(pubBytes);
            var addressBytes = new byte[pubHash.Length - 12];
            Array.Copy(pubHash, 12, addressBytes, 0, addressBytes.Length);
            var chsum = CaclulateChecksum(addressBytes, _networkId);
            var chsumBytes = chsum.HexToByteArray();

            var fullAddress = new List<byte>(_networkId.Length + chsumBytes.Length + addressBytes.Length);
            fullAddress.AddRange(_networkId);
            fullAddress.AddRange(chsumBytes);
            fullAddress.AddRange(addressBytes);

            return (_addressBytes = fullAddress.ToArray());
        }

        public string GetAddressHex()
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
            result.AddRange(GetPublicKeyBytes());
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
        private string CaclulateChecksum(byte[] address, byte[] prefix)
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

        public static XcbECKey GenerateKey(string networkId = "cb", byte[] seed = null)
        {
            return GenerateKey(networkId.HexToByteArray(), seed);
        }

        public static XcbECKey GenerateKey(byte[] networkId, byte[] seed = null)
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

            return new XcbECKey(privateBytes, networkId);
        }
    }
}