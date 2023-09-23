using System;
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
            transaction.Sign(key);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8ce800a830f423f0b96ce276773ac97d16855a3c8faa45399136b56d419486081c880b8abb41038ce63d7c8c24004f14ae5d13be4b5d00a42445892fb007ab378ed8c7ebebbeeeacb33cbe47524cf31332c1e8c9457ed9d06f03bdfce8036cf9e3ad9b9fe4a3e7cc7848f7998e703879eab9c81b0ef3e2a16f027a5f626daa21280f89000688c00d37a896eb104199d0399e139c63300315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600",
                encodedHex);
        }
        
        [Fact]
        public void TransactionFullTestDevin()
        {
            //Given ab03a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5
            XcbECKey key = new XcbECKey("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", 3);

            Transaction transaction = new Transaction(to: "ab41eae08196c507c35beb0c9e4dbfe342c0b1fc99ee",
                amount: BigInteger.Parse("20000"),
                nonce: BigInteger.Parse("80"),
                energyLimit: BigInteger.Parse("999999"),
                energyPrice: BigInteger.Parse("100"),
                data: "");

            //When
            transaction.Sign(key);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8cf5064830f423f0396ab41eae08196c507c35beb0c9e4dbfe342c0b1fc99ee824e2080b8abf72984b9da3001425bd464f3d3abd960ea0bfcea734e97b61747ca164265931e42345de28dd43af20a3ea18756ef0b7c6ad0535489d16ed780b227e0d351a92fefa6b4a4c0c1b9a78b0b9c4ed7af933c61df11190b9852743ed35bcd89020bf0ab080cd071690f426bb2b38fc440c45f0700315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600",
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
            transaction.Sign(key);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8d301843b9aca008301869f0196cb3599b799bc6db3d54d496558fc2282cb70f72e8c2b8201f480b8abf305481db5650591e8733eac5aae17bf90f404b43ec836070c862506c9d88c9730bb4676972e0509f1b7891404495ecdd53af1996e814a5480e69e3ea852c0f742201147c37bc126c64f5add66ea6734efe793f4f4c207daaec4baabf8d27b3c19d8702e5bf798311dc6e6218cc9900f320067b522b53a55363b334c30eec79b491aef0bd4dbd59c9364b9f2e5890487c635825a681dd316f8ce010ccbbaa12ddfe8fc423a6c8f64e3f380",
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
            transaction.Sign(key);
            var encoded = transaction.GetRlpEncoding();
            var encodedHex = encoded.ToHex(true);

            var transaction2 = Transaction.Decode(encoded);
            var reEncode = transaction2.GetRlpEncoding();

            //Then
            Assert.Equal(encoded, reEncode);
            Assert.Equal("0xf8d302843b9aca008301869f0b96cb3599b799bc6db3d54d496558fc2282cb70f72e8c2b8201f480b8abb0c6e6f2f29f86f723a39775944e99ee71e69a29be49e887649a568012bc70af008d202349a29a3ba8836e3f95ad60f10ead1ba36e9137be00f1340c4ff9a053c7abafc729eaa06117d7667a84b37b6010243672ed96bcaf5a42285a6e9acaddca1e8857b0ffb78db3fc02a794dbe5b81f000b7f8b323c7ed6ee7539452cfb0578a990e90a6a7401174c941267c411289c452152d2d7cbe15986d662935f2ea989be074aaf0966251fc700",
                encodedHex);
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


        [Fact]
        public void TestFromGoCore()
        {
            //Given
            var privateKey =
                "2da94fd47e8369ffe88850654de266727ff284c3f78d61b04153cb9a908ed3b61248ac5172d3caabbc3493807c0297645ae328e10eb9543bdb";
            var key = new XcbECKey(privateKey, 1);

            var transaction = new Transaction("cb8238748ee459bc0c1d86eab1d3f6d83bb433cdad9c",
                new BigInteger(10),
                BigInteger.Zero,
                new BigInteger(10),
                new BigInteger(50000),
                "0x1123");
            
            transaction.Sign(key);

            var expectedSignedRlp =
                "f8ce800a82c3500196cb8238748ee459bc0c1d86eab1d3f6d83bb433cdad9c0a821123b8ab8b9a925c793208a401044d856b5b39cc6f1d963f1dc55f65296501ca90d1debf8705e30d8c27ae221eb11b15d9bc8dc739e37d952b517570803446e36d50c3cd1c38943b3d50141f69c64e38cdae0ef2ced9a34eadc5f628f7039f12462c68c509230403bcb3f517754b7689dee772ca1a00ba277941fcb9ac8063a9b6ed64fbc86c51dd5ae6cf1f01f7bcf533cf0b0cfc5dc3fdc5bc7eaa99366ada5e7127331b862586a46c12a85f9580";

            var signedRlp = transaction.GetRlpEncoding().ToHex();
            Assert.Equal(expectedSignedRlp,signedRlp);
        }
    }
}
