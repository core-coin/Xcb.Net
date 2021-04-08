

using System.Numerics;
using Xcb.Net.Extensions;
using Xcb.Net.Model;
using Xcb.Net.RLP;

namespace Xcb.Net.Signer
{
    public class Transaction
    {

        public const int NUMBER_ENCODING_ELEMENTS = 6;
        public static readonly BigInteger DEFAULT_ENERGY_PRICE = BigInteger.Parse("20000000000");
        public static readonly BigInteger DEFAULT_ENERGY_LIMIT = BigInteger.Parse("21000");
        public byte[][] Data { get; private set; }

        public byte[] Signature { get; private set; }


        public Transaction(byte[] nonce, byte[] energyPrice, byte[] energyLimit, byte[] receiveAddress, byte[] value,
            byte[] data)
        {
            Data = GetElementsInOrder(nonce, energyPrice, energyLimit, receiveAddress, value, data);
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce)
            : this(to, amount, nonce, DEFAULT_ENERGY_PRICE, DEFAULT_ENERGY_LIMIT)
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, string data)
            : this(to, amount, nonce, DEFAULT_ENERGY_PRICE, DEFAULT_ENERGY_LIMIT, data)
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, BigInteger energyPrice, BigInteger energyLimit)
            : this(to, amount, nonce, energyPrice, energyLimit, "")
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, BigInteger energyPrice,
            BigInteger energyLimit, string data) : this(nonce.ToBytesForRLPEncoding(), energyPrice.ToBytesForRLPEncoding(),
            energyLimit.ToBytesForRLPEncoding(), to.HexToByteArray(), amount.ToBytesForRLPEncoding(), data.HexToByteArray()
        )
        {
        }

        private byte[] GetEncodedRaw()
        {
            var rlpRawWitNoSignature = RLP.RLP.EncodeElementsAndList(Data);
            return rlpRawWitNoSignature;
        }

        private byte[][] GetElementsInOrder(byte[] nonce, byte[] energyPrice, byte[] energyLimit, byte[] receiveAddress,
            byte[] value,
            byte[] data)
        {
            if (receiveAddress == null)
                receiveAddress = DefaultValues.EMPTY_BYTE_ARRAY;
            //order  nonce, energyPrice, energyLimit, receiveAddress, value, data
            return new[] { nonce, energyPrice, energyLimit, receiveAddress, value, data };
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