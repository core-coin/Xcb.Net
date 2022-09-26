using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xcb.Net.Extensions;
using Xcb.Net.Signer;

namespace Xcb.Net.Signer.EIP712
{
    public class XcbMessageSigner : MessageSigner
    {
        public override string EcRecover(byte[] message, string signature, int networkId)
        {
            return base.EcRecover(HashPrefixedMessage(message), signature, networkId);
        }

        public byte[] HashAndHashPrefixedMessage(byte[] message)
        {
            return HashPrefixedMessage(Hash(message));
        }

        public override string HashAndSign(byte[] plainMessage, XcbECKey key)
        {
            return base.Sign(HashAndHashPrefixedMessage(plainMessage), key);
        }

        public byte[] HashPrefixedMessage(byte[] message)
        {
            var byteList = new List<byte>();
            var bytePrefix = "0x19".HexToByteArray();
            var textBytePrefix = Encoding.UTF8.GetBytes("Ethereum Signed Message:\n" + message.Length);

            byteList.AddRange(bytePrefix);
            byteList.AddRange(textBytePrefix);
            byteList.AddRange(message);
            return Hash(byteList.ToArray());
        }

        public override string Sign(byte[] message, XcbECKey key)
        {
            return base.Sign(HashPrefixedMessage(message), key);
        }

        public string EncodeUTF8AndSign(string message, XcbECKey key)
        {
            return base.Sign(HashPrefixedMessage(Encoding.UTF8.GetBytes(message)), key);
        }

        public string EncodeUTF8AndEcRecover(string message, string signature, int networkId)
        {
            return EcRecover(Encoding.UTF8.GetBytes(message), signature, networkId);
        }
    }
}