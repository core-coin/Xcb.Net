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
            XcbECKey key = new XcbECKey("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", 11);

            Transaction transaction = new Transaction(to: "ce276773ac97d16855a3c8faa45399136b56d4194860",
            amount: BigInteger.Parse("200"),
            nonce: BigInteger.Parse("0"),
            energyLimit: BigInteger.Parse("999999"),
            energyPrice: BigInteger.Parse("10"),
            data: "");

            //When
            transaction.Sign(key, 0);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8ce800a830f423f8096ce276773ac97d16855a3c8faa45399136b56d419486081c880b8ab448eafc4ad76f52262dc04c09738e017dbf7dac5cee6d7bf0a8c0b60aaa1403d10e3d3a28f2d0ce9a9ffb64ebb9e0a59a3637f0f48aa597f80722d2c29acab15b7e2677f3df91ea86ecbb0f6cc871fdf39a154262ed467ae6e2996cdc09dbce205c318b7581d28bae84c0eb3d118edf61000315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600",
                encodedHex);
        }

        [Fact]
        public void TransactionWithNormalPrivateKeyTest()
        {
            //Given
            XcbECKey key = new XcbECKey("e90d87a86d14321252ed4d1c7a5652b62112a8269343c04c1a69a5e218710371aa20e54f75b2b9d5fea220b5739e5fa93ec6ea92ee9ec92c00", 1);

            Transaction transaction = new Transaction(to: "cb3599b799bc6db3d54d496558fc2282cb70f72e8c2b",
            amount: BigInteger.Parse("500"),
            nonce: BigInteger.Parse("1"),
            energyLimit: BigInteger.Parse("99999"),
            energyPrice: BigInteger.Parse("1000000000"),
            data: "");

            //When
            transaction.Sign(key, 0);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8d301843b9aca008301869f8096cb3599b799bc6db3d54d496558fc2282cb70f72e8c2b8201f480b8ab75ba144a0aad7a63d6bd89972c69ce7e4e25d484aa4f8d33fbfc06fa76ffce1364e0054d5225a86bf66c91d2697dcb2f75bdd9dd35e34d1c80dcd67f147902ac0bc08d03e924fb4ee5016b793d2d5e31d0dbe21a2dda17d68060796de8c3fe325dc0c8fb98dcfb672f2a4aeddb245eb51f0067b522b53a55363b334c30eec79b491aef0bd4dbd59c9364b9f2e5890487c635825a681dd316f8ce010ccbbaa12ddfe8fc423a6c8f64e3f380",
                encodedHex);
        }

        [Fact]
        public void TransactionWithExtendedPrivateKeyTest()
        {
            //Given
            XcbECKey key = new XcbECKey("e90d87a86d14321252ed4d1c7a5652b62112a8269343c04c1a69a5e218710371aa20e54f75b2b9d5fea220b5739e5fa93ec6ea92ee9ec92cdd", 11);

            Transaction transaction = new Transaction(to: "cb3599b799bc6db3d54d496558fc2282cb70f72e8c2b",
            amount: BigInteger.Parse("500"),
            nonce: BigInteger.Parse("2"),
            energyLimit: BigInteger.Parse("99999"),
            energyPrice: BigInteger.Parse("1000000000"),
            data: "");

            //When
            transaction.Sign(key, 0);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8d302843b9aca008301869f8096cb3599b799bc6db3d54d496558fc2282cb70f72e8c2b8201f480b8abffd9a99602b23626778212ca5c679163ab5d8a89b1506d36f2b10971c3d2a76ab296d0348a1fda23ccde3bcca2f209c74a951da7845305c2804e6a556991f0f8b5a7d1843399bdaa807fcf7d0b3c04d29ad9d2f81d809c55cbad50ce0ae80eb7ae93b2999b0bfdd67b5856d6c2cf8a9e10000b7f8b323c7ed6ee7539452cfb0578a990e90a6a7401174c941267c411289c452152d2d7cbe15986d662935f2ea989be074aaf0966251fc700",
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
