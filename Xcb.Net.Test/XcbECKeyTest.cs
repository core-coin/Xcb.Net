using System;
using Xcb.Net.Signer;
using Xunit;
using Xcb.Net.Extensions;
using Org.BouncyCastle.Security;
using System.Threading.Tasks;
using Org.BouncyCastle.Math.EC.Rfc8032;

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
            Assert.ThrowsAny<Exception>(() => new XcbECKey(privateKey, 1));
        }

        [Theory]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", 1, "cb82a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5")]
        [InlineData("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", 11, "ce73a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5")]
        public void AddressGeneration(string privateKey, int networkId, string expectedAddress)
        {
            var key = new XcbECKey(privateKey, networkId);
            Assert.Equal(expectedAddress, key.GetAddressHex());
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

        [Theory]
        [InlineData("", "", "3ce162133cb2bd775b6d74eb03516a2ca837b41eeaa06df9b88392813384ccb0f7e5514ea9e516a1d0e519e2dd8f5dde1c3f519dcb651ef961")]
        public void TestPbkdf2Hash(string password, string salt, string expectedHash)
        {
            var hd = new HDWallet.HDWallet();
            var passwordBytes = password.HexToByteArray();
            var saltBytes = salt.HexToByteArray();
            var hash = hd.pbkdf2_sha3_256(passwordBytes, saltBytes, 2048, 57).ToHex();

            Assert.Equal(hash, expectedHash);
        }

        [Theory]
        [InlineData(0, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    0, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                       "2b8b869522818a20236163e0db07800fef1ad2178c0d2c095658207f26a5f8b001ca1693091eddf81d103628caa721f93abf34400be71d17ac")]
        public void TestConcatenateHex(byte prefix, string password, uint index, string salt, string expectedHash)
        {
            var hd = new HDWallet.HDWallet();
            var passwordBytes = password.HexToByteArray();
            var saltBytes = salt.HexToByteArray();
            var hash = hd.concatenateAndHex(prefix, passwordBytes, index, saltBytes).ToHex();


            Assert.Equal(hash, expectedHash);
        }

        [Theory]
        [InlineData("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594",
        "004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0db615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880")]
        public void TestExtendedPrivateToPublic(string priv, string expectedPublic)
        {
            var hd = new HDWallet.HDWallet();
            var keyBytes = priv.HexToByteArray();
            var pub = hd.extendedPrivateToPublic(keyBytes).ToHex();

            Assert.Equal(pub, expectedPublic);
        }

        [Theory]
        [InlineData("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594",
        "004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0db615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880",
        "aa156b")]
        public void TestExtendedKeySignature(string priv, string publicKey, string message)
        {
            var key = new XcbECKey(priv.HexToByteArray()[57..114], 1);
            var sign = key.SignHashOfMessage(message.HexToByteArray());
            var pub = XcbECKey.GetPublicKeyFromSignature(sign);
            Assert.Equal(publicKey.HexToByteArray()[57..114], pub);

            var wallet = new HDWallet.HDWallet();
            var xpri1 = wallet.childPrivateToPrivate(priv.HexToByteArray(), 10);
            var xpub1 = wallet.childPublicToPublic(publicKey.HexToByteArray(), 10);

            var key1 = new XcbECKey(xpri1[57..114],1);
            var sign1 = key1.SignHashOfMessage(message.HexToByteArray());
            var r_pub = XcbECKey.GetPublicKeyFromSignature(sign1);
            Assert.Equal(r_pub, xpub1[57..114]);

        }

        [Theory]
        [InlineData("757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99",
        0, "b8254111ddf243fd897b44878678ff15d16763c7939e86512fd2b6d6535fde62ec6c94dd61fc76033d94e001ea26ef3950a0edd2ef74713760e63a36576ee565e08646a99c2062ebdf773167dc533a0a3a1b0d929d8b77b5faf7d54d557f3b537eeb572b04b04d246fb63154381679a48e99")]
        [InlineData("88b8592017482e0d85a8c405b84e12ba3a8ac552198216b0da811adc368589cc86a8bb38c67c766f9a942e7cedf5a6a36338f3d5bdd9466e2554b229028a76f79a18f4171fea287db096f05cc62ff3246ec70a2ebbf896b094350650846703183c09a13790e93fd3110c3ec0fe338daf93ba",
        0x80000000, "bd9c963ce9ac0fb9da7f9dfa0ea84251ed6f3eba924858bb7b2f9eb3a66aa4fb42a87a0d5b05c9a48c442b480477d17cd89b8679acd6ccdf02fca262c2f9a158d51bea28d0b2724f237560f65a3b8ae98215dc97ade43beb1e3dad4fc12ec8a81da661db0ab6b94f1c566e38f16e8daf93ba")]
        public void TestChildPrivateToPrivate(string priv, uint index, string expectedPrivate)
        {
            var hd = new HDWallet.HDWallet();
            var privBytes = priv.HexToByteArray();
            var priv1 = hd.childPrivateToPrivate(privBytes, index).ToHex();

            Assert.Equal(priv1, expectedPrivate);
        }

        [Theory]
        [InlineData("08288c75a01cafb05193567fb285b66767a6d393b7763f3f085f140ac0ad59b56dfdae70533f112a67cbd359910b2c5f1c8916bf6f593a5db4e7e1d0e85a354edc803d39f89923aadd362da91693cbb01206b86b3173039e18513a9964f96f34aa27b275d9a81b50905ebc860905e1c51700",
        0, "0c051354b0efede7fa00124dd9e5a37bb7f0edf157b8139f64be5f6cac2c5edc7c60e1c4245136e9b9b8ea7f9ef5ab20032f6c6f2dba07d7f44a5aa538883ce7a9115337293eedb620ee031b71e994936557e58ef1dbafd1f91413c154b8713c43150a14e11c0ce0ba1d6d55bd26802d2080")]
        public void TestChildPublicToPublic(string pub, uint index, string expectedPublic)
        {
            var hd = new HDWallet.HDWallet();
            var pubBytes = pub.HexToByteArray();
            var priv1 = hd.childPublicToPublic(pubBytes, index).ToHex();

            Assert.Equal(priv1, expectedPublic);
        }

        [Theory]
        [InlineData()]
        public void TestMassDerive()
        {
            var hd = new HDWallet.HDWallet();
            byte[] priv1 = new byte[114];
            byte[] priv2 = new byte[114];
            priv1 = "757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99".HexToByteArray();
            priv2 = "757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99".HexToByteArray();
            for (uint i = 0; i < 100; i++)
            {
                priv1 = hd.childPrivateToPrivate(priv1, i);
            }
            priv1 = hd.extendedPrivateToPublic(priv1);
            priv2 = hd.extendedPrivateToPublic(priv2);
            for (uint i = 0; i < 100; i++)
            {
                priv2 = hd.childPublicToPublic(priv2, i);
            }
            Assert.Equal(priv1, priv2);
        }

        [Theory]
        [InlineData("6bc0169565eecbc8e62259959534a67684adbd4c229cc8830405fe81f60c7b896a273421c9587f4b3321ab8353bf7178b8f383ce07f916de7abebabfef0f5fee", "348728c67f8827c5fac17c81c17cba245c957ee16d115def1802cb39d637fb682047b054f3eb4b169477d845b3b4d7c87fa36ec3e7e98d0c0361f1dc6767753ca9db7ed41c32a745d7930121feba01b9b9ad0a6774dc906e8775c3eedb26037e4c2ffceccc198df6f97f9c7f2d79b89baf85")]
        public void TestSeedToMaster(string seed, string expectedMaster)
        {
            var hd = new HDWallet.HDWallet();
            var seedBytes = seed.HexToByteArray();
            var master = hd.seedToMaster(seedBytes).ToHex();

            Assert.Equal(master, expectedMaster);
        }

        [Theory]
        [InlineData("e7e1d0e85a354edc803d39f89923aadd362da91693cbb01206b86b3173039e18513a9964f96f34aa27b275d9a81b50905ebc860905e1c51700",
                    "e499153bdb58768a79df0ae69beb332de0704f08575c82587c1f8227d43fdccf92b64571831ec3f022e9212c0f1629d8f7e175c59800000000",
                    "4a5aa538883ce7a9115337293eedb620ee031b71e994936557e58ef1dbafd1f91413c154b8713c43150a14e11c0ce0ba1d6d55bd26802d2080")]
        [InlineData("c20d46aaaea91e969024b6f0814eca05acce94b21173324f8c4c5ce47359b6cde3dda770fae8541ce47b1b13fdf8f9775b40d2af68a09ff680",
                    "e4135f5926a506eeae7980aa747a7d368fead4bfab3e0c1d91d76588045bc347db8507c80c09e020795ec8ce05feb54b0bfb8a606c00000000",
                    "6a8a9e1f520a2cab30ff246e233b0687ed7f6e88902d4cb66d35af9ebc6b45ee65c94454b54b82923b31ed6b84cad9cbe77b329977c1fd2480")]
        public void TestShiftPublic(string pub1, string shift, string pub2)
        {
            byte[] pub = new byte[57];
            Ed448.ShiftPublic(pub1.HexToByteArray(), shift.HexToByteArray(), pub);

            Assert.Equal(pub.ToHex(), pub2);
        }

        [Fact]
        public void GenerateWithSeed()
        {
            //Given
            var masterSeed = "0x3c60d7ebb9e828bbe63b116bf7a7c21dfb61e5ccf3594639bdffe89eab44e200".HexToByteArray();

            //When
            var key = XcbECKey.GenerateKey(1, masterSeed);
            Task.Delay(1000).Wait();
            var key2 = XcbECKey.GenerateKey(1, masterSeed);

            //Then
            Assert.Equal(key.GetAddressHex(), key2.GetAddressHex());
        }
    }
}
