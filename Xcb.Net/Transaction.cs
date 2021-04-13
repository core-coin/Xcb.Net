

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

        public byte[] AccountNone { get; set; }

        public byte[] EnergyPrice { get; set; }

        public byte[] EnergyLimit { get; set; }

        public byte[] RecipientAddress { get; set; }

        public byte[] Amount { get; set; }

        public byte[] Payload { get; set; }

        public byte[] ChainId { get; set; }

        public byte[] Signature { get; private set; }


        public Transaction(byte[] nonce, byte[] energyPrice, byte[] energyLimit, byte[] receiveAddress, byte[] value,
            byte[] data, byte[] chainId)
        {

        }

        public Transaction(string to, BigInteger amount, BigInteger nonce)
            : this(to, amount, nonce, DEFAULT_ENERGY_PRICE, DEFAULT_ENERGY_LIMIT)
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, string data)
            : this(to, amount, nonce, DEFAULT_ENERGY_PRICE, DEFAULT_ENERGY_LIMIT, data, BigInteger.Zero)
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, string data, BigInteger chainId)
            : this(to, amount, nonce, DEFAULT_ENERGY_PRICE, DEFAULT_ENERGY_LIMIT, data, chainId)
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, BigInteger chainId)
            : this(to, amount, nonce, DEFAULT_ENERGY_PRICE, DEFAULT_ENERGY_LIMIT, "", chainId)
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, BigInteger energyPrice, BigInteger energyLimit)
            : this(to, amount, nonce, energyPrice, energyLimit, "", BigInteger.Zero)
        {
        }

        public Transaction(string to, BigInteger amount, BigInteger nonce, BigInteger energyPrice,
            BigInteger energyLimit, string data, BigInteger chainId) : this(nonce.ToBytesForRLPEncoding(), energyPrice.ToBytesForRLPEncoding(),
            energyLimit.ToBytesForRLPEncoding(), to.HexToByteArray(), amount.ToBytesForRLPEncoding(), data.HexToByteArray(), chainId.ToBytesForRLPEncoding()
        )
        {
        }

    }
}