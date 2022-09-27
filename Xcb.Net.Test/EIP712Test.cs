using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Nethereum.ABI.EIP712;
using Nethereum.ABI.FunctionEncoding.Attributes;
using Xcb.Net.EIP712;
using Xcb.Net.Signer;
using Xunit;

namespace Xcb.Net.Test
{
    public class EIP712Test
    {
        class Withdraw2fa
        {
            [Parameter("string", "coin", 1)]
            public virtual string Coin { get; set; }
            [Parameter("uint32", "decimals", 2)]
            public virtual int Decimals { get; set; }
            [Parameter("uint256", "amout", 3)]
            public virtual BigInteger Amount { get; set; }
            [Parameter("uint256", "fee", 4)]
            public virtual BigInteger Fee { get; set; }
            [Parameter("string", "destination", 5)]
            public virtual string Destination { get; set; }

            [Parameter("uint256", "time", 6)]
            public virtual BigInteger Time { get; set; }
        }

        private static TypedData<Domain> getTypedData(Domain domain)
        {
            var typedData = new TypedData<Domain>
            {
                Domain = domain,
                Types = new Dictionary<string, MemberDescription[]>
                {
                    ["EIP712Domain"] = new[]
                    {
                        new MemberDescription {Name = "name", Type = "string"},
                        new MemberDescription {Name = "version", Type = "string"},
                        new MemberDescription {Name = "chainId", Type = "uint256"},
                        new MemberDescription {Name = "verifyingContract", Type = "address"},
                    },
                    ["WithdrawData"] = new[]{
                        new MemberDescription {Name = "coin", Type = "string"},
                        new MemberDescription {Name = "amount", Type = "unint256"},
                        new MemberDescription {Name = "decimals", Type = "uint32"},
                        new MemberDescription {Name = "destination", Type = "string"},
                        new MemberDescription {Name = "fee", Type = "uint256"},
                        new MemberDescription {Name = "time", Type = "uint256"}
                    }
                },
                PrimaryType = "WithdrawData"
            };

            return typedData;
        }

        [Fact]
        public void PingExchange2FATest()
        {
            // Given
            var corepassId = "cb82a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5";
            var key = new XcbECKey("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", 1);

            Eip712TypedDataSigner _signer = new Eip712TypedDataSigner();
            var typedData = getTypedData(new Domain
            {
                Name = "Ping",
                Version = "1.0.0",
                ChainId = 1337,
                VerifyingContract = "cb868a301d28f082e1ea79f0f1e0038aff7f47564b0e"
            });

            var withdraw = new Withdraw2fa
            {
                Amount = 1000000,
                Decimals = 100_000_000,
                Coin = "BTC",
                Destination = "bc1qs7gd29ptzvyc8s9etpcp07xny6v6krz3jhklya",
                Fee = 1000,
                Time = ((DateTimeOffset)DateTime.Parse("2022-7-11 17:34:00")).ToUnixTimeSeconds()
            };

            var verifier = new Eip712TypedDataSigner();

            // When
            var signature = _signer.SignTypedDataV4(withdraw, typedData, key);
            var addressRecovered2 = verifier.RecoverFromSignatureV4(typedData, signature, 1);
            var addressRecovered = verifier.RecoverFromSignatureV4(withdraw, typedData, signature, 1);
            var address = key.GetAddress();

            // Then
            Assert.Equal(corepassId, address);
            Assert.Equal(addressRecovered, addressRecovered2);
            Assert.Equal(corepassId,addressRecovered);
        }
    }
}