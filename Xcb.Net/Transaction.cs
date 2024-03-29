

using System.Numerics;
using Xcb.Net.Extensions;
using Xcb.Net.Model;
using Xcb.Net.RLP;

namespace Xcb.Net.Signer
{
    public class Transaction
    {

        public const int NUMBER_ENCODING_ELEMENTS = 7;
        public static readonly BigInteger DEFAULT_ENERGY_PRICE = BigInteger.Parse("20000000000");
        public static readonly BigInteger DEFAULT_ENERGY_LIMIT = BigInteger.Parse("21000");

        public byte[] AccountNonce { get; set; }

        public byte[] EnergyPrice { get; set; }

        public byte[] EnergyLimit { get; set; }

        public byte[] RecipientAddress { get; set; }

        public byte[] Amount { get; set; }

        public byte[] Payload { get; set; }

        public byte[] NetworkId { get; private set; }

        public byte[] Signature { get; private set; }


        public Transaction(byte[] nonce, byte[] energyPrice, byte[] energyLimit, byte[] receiveAddress, byte[] value,
            byte[] data)
        {
            this.AccountNonce = nonce ?? DefaultValues.EMPTY_BYTE_ARRAY;
            this.EnergyPrice = energyPrice ?? DefaultValues.EMPTY_BYTE_ARRAY;
            this.EnergyLimit = energyLimit ?? DefaultValues.EMPTY_BYTE_ARRAY;
            this.RecipientAddress = receiveAddress ?? DefaultValues.EMPTY_BYTE_ARRAY;
            this.Amount = value ?? DefaultValues.EMPTY_BYTE_ARRAY;
            this.Payload = data ?? DefaultValues.EMPTY_BYTE_ARRAY;
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

        private byte[] GetRawEncoding()
        {
            byte[] encoding = RLP.RLP.EncodeElementsAndList(
                this.AccountNonce,
                this.EnergyPrice,
                this.EnergyLimit,
                this.RecipientAddress,
                this.Amount,
                this.Payload,
                this.NetworkId
                );

            return encoding;
        }

        public byte[] GetRlpEncoding()
        {
            byte[] encoding = RLP.RLP.EncodeElementsAndList(
                this.AccountNonce,
                this.EnergyPrice,
                this.EnergyLimit,
                this.NetworkId,
                this.RecipientAddress,
                this.Amount,
                this.Payload,
                this.Signature
                );

            return encoding;
        }

        public byte[] GetTxHash()
        {
            byte[] hash = Util.Sha3NIST.Current.CalculateHash(GetRawEncoding());
            return hash;
        }

        public string GetTxHashId()
        {

            byte[] hash = Util.Sha3NIST.Current.CalculateHash(GetRlpEncoding());
            return hash.ToHex(true);
        }

        public void Sign(XcbECKey key)
        {
            this.NetworkId = new BigInteger(key.NetworkId).ToBytesForRLPEncoding();
            
            byte[] hash = GetTxHash();
            this.Signature = key.SignMessage(hash);
        }


        public static Transaction Decode(byte[] data)
        {
            var decodedList = (RLPCollection)RLP.RLP.Decode(data);

            var AccountNonce = decodedList[0].RLPData;
            var EnergyPrice = decodedList[1].RLPData;
            var EnergyLimit = decodedList[2].RLPData;
            var networkId = decodedList[3].RLPData;
            var RecipientAddress = decodedList[4].RLPData;
            var Amount = decodedList[5].RLPData;
            var Payload = decodedList[6].RLPData;
            var Signature = decodedList[7].RLPData;

            var transaction = new Transaction(
                nonce: AccountNonce,
                energyPrice: EnergyPrice,
                energyLimit: EnergyLimit,
                receiveAddress: RecipientAddress,
                value: Amount,
                data: Payload
            );

            transaction.Signature = Signature;
            transaction.NetworkId = networkId;

            return transaction;
        }
    }
}
