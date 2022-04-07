using Xunit;
using Xcb.Net.Extensions;
using Xcb.Net.HDWallet;
using Xcb.Net.Signer;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Xcb.Net.Test
{
    public class ExtendedKeyTests
    {

        [Theory]
        [InlineData("", "", "3ce162133cb2bd775b6d74eb03516a2ca837b41eeaa06df9b88392813384ccb0f7e5514ea9e516a1d0e519e2dd8f5dde1c3f519dcb651ef961")]
        public void TestPbkdf2Hash(string password, string salt, string expectedHash)
        {
            var passwordBytes = password.HexToByteArray();
            var saltBytes = salt.HexToByteArray();
            var hash = ExtendedKeyBase.Pbkdf2(passwordBytes, saltBytes).ToHex();

            Assert.Equal(hash, expectedHash);
        }

        [Theory]
        [InlineData(0, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    0, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                       "2b8b869522818a20236163e0db07800fef1ad2178c0d2c095658207f26a5f8b001ca1693091eddf81d103628caa721f93abf34400be71d17ac")]
        public void TestConcatenateHex(byte prefix, string password, uint index, string salt, string expectedHash)
        {
            var passwordBytes = password.HexToByteArray();
            var saltBytes = salt.HexToByteArray();
            var hash = ExtendedKeyBase.ConcatenateAndHex(prefix, passwordBytes, index, saltBytes).ToHex();

            Assert.Equal(hash, expectedHash);
        }

        [Theory]
        [InlineData("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594",
        "004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0db615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880")]
        public void TestExtendedPrivateToPublic(string priv, string expectedPublic)
        {
            var extPriv = (ExtendedPrivateKey)(priv.HexToByteArray());
            var pub = ((byte[])extPriv.ToExtendedPublicKey()).ToHex();

            Assert.Equal(pub, expectedPublic);
        }

        [Theory]
        [InlineData("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594",
        "004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0db615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880",
        "aa156b")]
        public void TestExtendedKeySignature(string priv, string publicKey, string message)
        {
            var extPrivate = (ExtendedPrivateKey)priv.HexToByteArray();
            var key = extPrivate.ToXcbECKey(1);
            var sign = key.SignHashOfMessage(message.HexToByteArray());
            var pub = XcbECKey.GetPublicKeyFromSignature(sign);
            var extPublic = (ExtendedPublicKey)publicKey.HexToByteArray();
            Assert.Equal(extPublic.GetPublicKey(), pub);


            var xpri1 = extPrivate.ToChildExtendedPrivateKey(10);
            var xpub1 = extPublic.ToChildExtendedPublicKey(10);

            var key1 = xpri1.ToXcbECKey(1);
            var sign1 = key1.SignHashOfMessage(message.HexToByteArray());
            var r_pub = XcbECKey.GetPublicKeyFromSignature(sign1);
            Assert.Equal(r_pub, xpub1.GetPublicKey());

        }

        [Theory]
        [InlineData("757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99",
        0, "b8254111ddf243fd897b44878678ff15d16763c7939e86512fd2b6d6535fde62ec6c94dd61fc76033d94e001ea26ef3950a0edd2ef74713760e63a36576ee565e08646a99c2062ebdf773167dc533a0a3a1b0d929d8b77b5faf7d54d557f3b537eeb572b04b04d246fb63154381679a48e99")]
        [InlineData("88b8592017482e0d85a8c405b84e12ba3a8ac552198216b0da811adc368589cc86a8bb38c67c766f9a942e7cedf5a6a36338f3d5bdd9466e2554b229028a76f79a18f4171fea287db096f05cc62ff3246ec70a2ebbf896b094350650846703183c09a13790e93fd3110c3ec0fe338daf93ba",
        0x80000000, "bd9c963ce9ac0fb9da7f9dfa0ea84251ed6f3eba924858bb7b2f9eb3a66aa4fb42a87a0d5b05c9a48c442b480477d17cd89b8679acd6ccdf02fca262c2f9a158d51bea28d0b2724f237560f65a3b8ae98215dc97ade43beb1e3dad4fc12ec8a81da661db0ab6b94f1c566e38f16e8daf93ba")]
        public void TestChildPrivateToPrivate(string priv, uint index, string expectedPrivate)
        {
            var privBytes = priv.HexToByteArray();
            var extPrivate = (ExtendedPrivateKey)privBytes;

            var priv1 = extPrivate.ToChildExtendedPrivateKey(index);

            Assert.Equal(((byte[])priv1).ToHex(), expectedPrivate);
        }

        [Theory]
        [InlineData("08288c75a01cafb05193567fb285b66767a6d393b7763f3f085f140ac0ad59b56dfdae70533f112a67cbd359910b2c5f1c8916bf6f593a5db4e7e1d0e85a354edc803d39f89923aadd362da91693cbb01206b86b3173039e18513a9964f96f34aa27b275d9a81b50905ebc860905e1c51700",
        0, "0c051354b0efede7fa00124dd9e5a37bb7f0edf157b8139f64be5f6cac2c5edc7c60e1c4245136e9b9b8ea7f9ef5ab20032f6c6f2dba07d7f44a5aa538883ce7a9115337293eedb620ee031b71e994936557e58ef1dbafd1f91413c154b8713c43150a14e11c0ce0ba1d6d55bd26802d2080")]
        public void TestChildPublicToPublic(string pub, uint index, string expectedPublic)
        {
            var extendedPublic = (ExtendedPublicKey)pub.HexToByteArray();
            var extPubHex = ((byte[])extendedPublic.ToChildExtendedPublicKey(index)).ToHex();

            Assert.Equal(extPubHex, expectedPublic);
        }

        [Fact]
        public void TestMassDerive()
        {

            var extendedPrivate0 = (ExtendedPrivateKey)"757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99".HexToByteArray();
            var extendedPrivate1 = (ExtendedPrivateKey)"757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99".HexToByteArray();

            for (uint i = 0; i < 100; i++)
            {
                extendedPrivate0 = extendedPrivate0.ToChildExtendedPrivateKey(i);
            }
            var expectedExtPub = extendedPrivate0.ToExtendedPublicKey();
            var massDeriveExtPub = extendedPrivate1.ToExtendedPublicKey();

            for (uint i = 0; i < 100; i++)
            {
                massDeriveExtPub = massDeriveExtPub.ToChildExtendedPublicKey(i);
            }

            Assert.Equal((byte[])expectedExtPub, (byte[])massDeriveExtPub);
        }

        [Theory]
        [InlineData("6bc0169565eecbc8e62259959534a67684adbd4c229cc8830405fe81f60c7b896a273421c9587f4b3321ab8353bf7178b8f383ce07f916de7abebabfef0f5fee", "348728c67f8827c5fac17c81c17cba245c957ee16d115def1802cb39d637fb682047b054f3eb4b169477d845b3b4d7c87fa36ec3e7e98d0c0361f1dc6767753ca9db7ed41c32a745d7930121feba01b9b9ad0a6774dc906e8775c3eedb26037e4c2ffceccc198df6f97f9c7f2d79b89baf85")]
        public void TestSeedToMaster(string seed, string expectedMaster)
        {
            var seedBytes = seed.HexToByteArray();
            var master = ExtendedPrivateKey.SeedToMaster(seedBytes);
            var masterHex = ((byte[])master).ToHex();

            Assert.Equal(masterHex, expectedMaster);
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

    }
}