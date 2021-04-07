using System;
using Xcb.Net.Signer;
using Xunit;
using Xcb.Net.Extensions;

namespace Xcb.Net.Test
{
    public class XcbEcKeyTest
    {
        [Fact]
        public void GenerateKey()
        {
            var key = XcbECKey.GenerateKey();

            Assert.NotNull(key);
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e",
            "315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        [InlineData("be2dca3a23e96807306c14354f99773e75a628e35712ac396bbee074bc9366f74d25d62ccfc0653139c04c8daaca0000b92147ebe0557ad0ac",
            "d6b96f877844ae137422944e113437745be7776e2712d43f5d93623a02c557193d2e4dc115bdc9220528678d1cfe8a73abf1cc56c2e4c53700")]
        public void Constructor_WithValidKeys(string privateKey, string expectedPublicKey)
        {
            var key = new XcbECKey(privateKey);

            Assert.NotNull(key);
            Assert.NotNull(key.GetPublicKeyBytes());
            Assert.NotNull(key.GetPrivateKeyBytes());

            Assert.Equal(privateKey, key.GetPrivateKeyHex());
            Assert.Equal(expectedPublicKey, key.GetPublicKeyHex());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c")] // small length
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0eabb")] // big length
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3s0e")] //invalid character s
        public void Constructor_WithInvalidKeys(string privateKey)
        {
            Assert.Throws<Exception>(() => new XcbECKey(privateKey));
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", "cb82a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5")]
        public void AddressGeneration(string privateKey, string expectedAddress)
        {
            var key = new XcbECKey(privateKey);
            Assert.Equal(expectedAddress, key.GetAddressHex());
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", "666f6f",
            "9db1a4fd159ec8449cc970e3c1e1848445997fb988f0c3aa1edf91ddb84dd873eb8c43bf052e0a56b49911d9981892811a9e28f02fd7472680388dd2f617f46c67501aea757c5fca981b749f4c6f08b2d480f66c44eaf1df9c7d02b934d45e31ffa8a6c07a54773f5dc1c0e2975b98792200315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600")]
        public void SignHashOfMessageTest(string privateKey, string message, string expectedSignature)
        {
            var key = new XcbECKey(privateKey);
            var expectedBytes = expectedSignature.HexToByteArray();
            var signatureBytes = key.SignHashOfMessage(message.HexToByteArray());
            Assert.Equal(expectedBytes,signatureBytes);
        }
    }
}
