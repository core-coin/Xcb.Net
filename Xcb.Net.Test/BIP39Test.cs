using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xcb.Net.HDWallet;
using Xunit;

namespace Xcb.Net.Test
{
    public class BIP39Test
    {
        [Fact]
        public void ValidMnemonic()
        {
            // Given
            var validMnemonic = "urge genuine pelican eagle blouse emotion refuse fringe flock salute space climb marriage empower feature inform ostrich endless fault barely chronic shy couple wonder";

            // When
            var mnemonic = new BIP39.Mnemonic24(validMnemonic);
            var extPrivKey = mnemonic.ToExtendedPrivateKey();

            // Then
            Assert.NotNull(mnemonic);
            Assert.NotNull(extPrivKey);
        }

        [Fact]
        public void InvalidMnemonic()
        {
            // Given
            var validMnemonic = "zoo genuine pelican eagle blouse emotion refuse fringe flock salute space climb marriage empower feature inform ostrich endless fault barely chronic shy couple wonder";


            // When
            Assert.Throws<ArgumentException>(() => new BIP39.Mnemonic24(validMnemonic));
        }

        [Fact]
        public void GenerateMnemonic()
        {
            // Given

            // When
            var mnemonic = BIP39.Mnemonic24.GenerateMnemonic();

            // Then
            Assert.NotNull(mnemonic);
        }

        [Fact]
        public void Mnemonic_To_PrivateWallet()
        {
            // Given
            var mnemonicPhrase = "cabin alert minute verb sing accuse chest pause scatter jealous bronze cruise phrase bench senior cube march job left pencil short glide hat sketch";


            // When
            var mnemonic = new Xcb.Net.BIP39.Mnemonic24(mnemonicPhrase);
            var extendedPrivateKey = mnemonic.ToExtendedPrivateKey();
            var privateWallet = PrivateWallet.GetPrivateWalletAtSpecificDerivationPath(extendedPrivateKey, "m/44'/654'/0'/0/0");

            var privateKey = privateWallet.GetPrivateKey();
            var xcbEcKey = privateWallet.GetXcbECKey(3);

            // Then
            Assert.NotNull(privateKey);
            Assert.NotNull(xcbEcKey);
        }
    }
}