using System.Numerics;
using Xcb.Net.Signer;
using Xcb.Net.Extensions;
using Xunit;

namespace Xcb.Net.Test
{
    public class TransactionTest
    {
        [Fact]
        public void TransactionFullTest()
        {
            //Given
            XcbECKey key = new XcbECKey("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", "ce");

            Transaction transaction = new Transaction(to: "ce276773ac97d16855a3c8faa45399136b56d4194860",
            amount: BigInteger.Parse("200"),
            nonce: BigInteger.Parse("0"),
            energyLimit: BigInteger.Parse("999999"),
            energyPrice: BigInteger.Parse("10"),
            data: "",
            chainId: BigInteger.Parse("1"));

            //When
            transaction.Sign(key);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8ce800a830f423f0196ce276773ac97d16855a3c8faa45399136b56d419486081c880b8abe52a632e933174c41c9875c13bfc3fcdef9b78d0d14f98c5b855baedbdb19322eb05513079facf04d8b45a0024ca3afebbfeec80a3a5ecf20037d765fde3800f322e4fbda071ee5cf722dcdc99f635b4fe04c76ba1019664837ba01c119e21b118f3302401740fcbac9c5c6af35681391c00315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600",
                encodedHex);
        }

        [Fact]
        public void EmptyTransactionTest()
        {
            //Given

            //When

            //Then
        }

        [Fact]
        public void DecodeTransactionTest()
        {
            //Given
            var encoded = "0xf8ce800a830f423f0196ce276773ac97d16855a3c8faa45399136b56d419486081c880b8abe52a632e933174c41c9875c13bfc3fcdef9b78d0d14f98c5b855baedbdb19322eb05513079facf04d8b45a0024ca3afebbfeec80a3a5ecf20037d765fde3800f322e4fbda071ee5cf722dcdc99f635b4fe04c76ba1019664837ba01c119e21b118f3302401740fcbac9c5c6af35681391c00315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600".HexToByteArray();

            //When
            var transaction = Transaction.Decode(encoded);
            var reEncode = transaction.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
        }
    }
}