

using Xcb.Net.Model;

namespace Xcb.Net.Signer
{
    public class Transaction
    {
        public byte[][] Data { get; private set; }

        public byte[] Signature { get; private set; }
        private byte[] GetEncodedRaw()
        {
            var rlpRawWitNoSignature = RLP.RLP.EncodeElementsAndList(Data);
            return rlpRawWitNoSignature;
        }

        private byte[][] GetElementsInOrder(byte[] nonce, byte[] gasPrice, byte[] gasLimit, byte[] receiveAddress,
            byte[] value,
            byte[] data)
        {
            if (receiveAddress == null)
                receiveAddress = DefaultValues.EMPTY_BYTE_ARRAY;
            //order  nonce, gasPrice, gasLimit, receiveAddress, value, data
            return new[] { nonce, gasPrice, gasLimit, receiveAddress, value, data };
        }

        public byte[] RawHash
        {
            get
            {
                var plainMsg = GetEncodedRaw();
                return Util.Sha3NIST.Current.CalculateHash(plainMsg);
            }
        }

        public void Sign(XcbECKey key)
        {
            Signature = key.SignMessage(RawHash);
        }
    }
}