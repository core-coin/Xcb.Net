using System;
using Xcb.Net.Signer;
using Xunit;
using Xcb.Net.Extensions;
using Org.BouncyCastle.Extended.Security;
using System.Threading.Tasks;
using Org.BouncyCastle.Extended.Math.EC.Rfc8032;

namespace Xcb.Net.Test
{
    public class XcbEcKeyTest
    {
        [Fact]
        public void GenerateKey()
        {
            var key = XcbECKey.GenerateKey(1);

            Assert.NotNull(key);
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e",
            "315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        [InlineData("59fc82f514f3fc8d02d987e52a03cdcae81a257bed6ec9b668bf6acd8fe9e7d27cbcc4d8f463d917642d30e7ca44c3521370f78790b3b561dd",
            "3cba3b2560c2779170ce5947f55bf73b93a1dd51d99b0b483ed0cfb5a9bb8409830c0f96068c799dbc6a28ca6bc1aad95d0387c36a731d7800")]
        [InlineData("a8ea212cc24ae0fd029a97b64be540885af0e1b7dc9faf4a591742850c4377f857ae9a8f87df1de98e397a5867dd6f20211ef3f234ae71bc56",
            "b615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880")]
        public void Constructor_WithValidKeys(string privateKey, string expectedPublicKey)
        {
            var key = new XcbECKey(privateKey, 1);

            Assert.NotNull(key);
            Assert.NotNull(key.GetPublicKey());
            Assert.NotNull(key.GetPrivateKey());

            Assert.Equal(privateKey, key.GetPrivateKey().ToHex());
            Assert.Equal(expectedPublicKey, key.GetPublicKey().ToHex());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c")] // small length
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0eabb")] // big length
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3s0e")] //invalid character s
        public void Constructor_WithInvalidKeys(string privateKey)
        {
            Assert.ThrowsAny<Exception>(() => new XcbECKey(privateKey, 1));
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", 1, "cb82a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5")]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", 11, "ce73a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5")]
        public void AddressGeneration(string privateKey, int networkId, string expectedAddress)
        {
            var key = new XcbECKey(privateKey, networkId);
            Assert.Equal(expectedAddress, key.GetAddress());
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", "666f6f",
            "ec1b749ebdc4884f4d6bd75f6f7ba0833f4caee116ed5088447f7522a05c4d24f07922ec69fc30dbf286fe9b5d0fa91bd26290f0b4d7b14100b1b5012c68da75b1385aa981b4b4d0d8fe1d754d76ca8f44e723f964d041ceca3a36a651755afe168e45cb5a063b12ea8301bba26afbbf0e00315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        public void SignMessageTest(string privateKey, string message, string expectedSignature)
        {
            var key = new XcbECKey(privateKey, 1);
            var expectedBytes = expectedSignature.HexToByteArray();
            var signatureBytes = key.SignMessage(message.HexToByteArray());
            Assert.Equal(expectedBytes, signatureBytes);

        }

        [Theory]
        [InlineData("666f6f",
            "ec1b749ebdc4884f4d6bd75f6f7ba0833f4caee116ed5088447f7522a05c4d24f07922ec69fc30dbf286fe9b5d0fa91bd26290f0b4d7b14100b1b5012c68da75b1385aa981b4b4d0d8fe1d754d76ca8f44e723f964d041ceca3a36a651755afe168e45cb5a063b12ea8301bba26afbbf0e00315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        public void Verify_Valid_Signature(string message, string signature)
        {
            var signatureBytes = signature.HexToByteArray();

            var pureSignatureBytes = new byte[114];

            Array.Copy(signatureBytes, pureSignatureBytes, 114);
            Assert.True(Ed448.Verify(pureSignatureBytes, 0, signatureBytes, 114, Array.Empty<byte>(), message.HexToByteArray(), 0, message.HexToByteArray().Length));
        }

        [Theory]
        [InlineData("aaaf6f",
            "ec1b749ebdc4884f4d6bd75f6f7ba0833f4caee116ed5088447f7522a05c4d24f07922ec69fc30dbf286fe9b5d0fa91bd26290f0b4d7b14100b1b5012c68da75b1385aa981b4b4d0d8fe1d754d76ca8f44e723f964d041ceca3a36a651755afe168e45cb5a063b12ea8301bba26afbbf0e00315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        public void Verify_Invalid_Signature(string message, string signature)
        {
            var signatureBytes = signature.HexToByteArray();

            var pureSignatureBytes = new byte[114];

            Array.Copy(signatureBytes, pureSignatureBytes, 114);
            Assert.False(Ed448.Verify(pureSignatureBytes, 0, signatureBytes, 114, Array.Empty<byte>(), message.HexToByteArray(), 0, message.HexToByteArray().Length));
        }

        [Theory]
        [InlineData("666f6f",
            "ec1b749ebdc4884f4d6bd75f6f7ba0833f4caee116ed5088447f7522a05c4d24f07922ec69fc30dbf286fe9b5d0fa91bd26290f0b4d7b14100b1b5012c68da75b1385aa981b4b4d0d8fe1d754d76ca8f44e723f964d041ceca3a36a651755afe168e45cb5a063b12ea8301bba26afbbf0e00315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600",
            "cb82a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5", 1)]
        public void RecoverFromSignature(string message, string signature, string expectedAddress, int networkId)
        {
            var address = XcbECKey.RecoverFromSignature(signature.HexToByteArray(), message.HexToByteArray(), networkId);
            Assert.Equal(expectedAddress, address);
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", "666f6f",
            "9db1a4fd159ec8449cc970e3c1e1848445997fb988f0c3aa1edf91ddb84dd873eb8c43bf052e0a56b49911d9981892811a9e28f02fd7472680388dd2f617f46c67501aea757c5fca981b749f4c6f08b2d480f66c44eaf1df9c7d02b934d45e31ffa8a6c07a54773f5dc1c0e2975b98792200315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        public void SignHashOfMessageTest(string privateKey, string message, string expectedSignature)
        {
            var key = new XcbECKey(privateKey, 1);
            var expectedBytes = expectedSignature.HexToByteArray();
            var signatureBytes = key.SignHashOfMessage(message.HexToByteArray());
            Assert.Equal(expectedBytes, signatureBytes);
        }

        [Theory]
        [InlineData("9db1a4fd159ec8449cc970e3c1e1848445997fb988f0c3aa1edf91ddb84dd873eb8c43bf052e0a56b49911d9981892811a9e28f02fd7472680388dd2f617f46c67501aea757c5fca981b749f4c6f08b2d480f66c44eaf1df9c7d02b934d45e31ffa8a6c07a54773f5dc1c0e2975b98792200315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600"
        , "315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        public void RecoverPublicKeyFromSignature(string signature, string expectedPublicKey)
        {
            var signatureBytes = signature.HexToByteArray();

            var publicKey = XcbECKey.GetPublicKeyFromSignature(signatureBytes).ToHex();


            Assert.Equal(expectedPublicKey, publicKey);
        }
    }
}
