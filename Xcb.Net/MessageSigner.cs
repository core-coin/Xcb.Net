using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xcb.Net.Extensions;

namespace Xcb.Net.Signer
{
    public class MessageSigner
    {
        public virtual string EcRecover(byte[] hashMessage, string signature, int networkId)
        {
            var signatureBytes = signature.HexToByteArray();
            return XcbECKey.RecoverFromSignature(signatureBytes, hashMessage, networkId);
        }

        public virtual string EcRecover(byte[] hashMessage, byte[] signature, int networkId)
        {
            return XcbECKey.RecoverFromSignature(signature, hashMessage, networkId);
        }

        public byte[] Hash(byte[] plainMessage)
        {
            return Util.Sha3NIST.Current.CalculateHash(plainMessage);
        }

        public virtual string HashAndEcRecover(string plainMessage, string signature, int networkId)
        {
            return EcRecover(Hash(Encoding.UTF8.GetBytes(plainMessage)), signature, networkId);
        }

        public string HashAndSign(string plainMessage, string privateKey, int networkId)
        {
            return HashAndSign(Encoding.UTF8.GetBytes(plainMessage), new XcbECKey(privateKey.HexToByteArray(), networkId));
        }

        public string HashAndSign(byte[] plainMessage, string privateKey, int networkId)
        {
            return HashAndSign(plainMessage, new XcbECKey(privateKey.HexToByteArray(), networkId));
        }

        public virtual string HashAndSign(byte[] plainMessage, XcbECKey key)
        {
            var hash = Hash(plainMessage);
            var signature = key.SignMessage(hash);
            return signature.ToHex();
        }

        public string Sign(byte[] message, string privateKey, int networkId)
        {
            return Sign(message, new XcbECKey(privateKey.HexToByteArray(), networkId));
        }

        public virtual string Sign(byte[] message, XcbECKey key)
        {
            var signature = key.SignMessage(message);
            return signature.ToHex();
        }
    }
}