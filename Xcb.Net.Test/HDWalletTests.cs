using Xcb.Net.HDWallet;
using Xunit;

namespace Xcb.Net.Test
{
    public class HDWalletTests
    {
        [Fact]
        public void PrivateWalletDerivationTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();
            PrivateWallet privateWallet =
                PrivateWallet.GetPrivateWalletAtSpecificDerivationPath(masterPrivateKey, "m/84'/0'/8'");

            // When
            var derivedPrivateKey = privateWallet.GetPrivateKey(20);
            var expectedDerivedPrivateKey = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToChildExtendedPrivateKey(20)
                .GetPrivateKey();

            // Then
            Assert.Equal(expectedDerivedPrivateKey, derivedPrivateKey);
        }

        [Fact]
        public void PublicWalletDerivationTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();

            PublicWallet publicWallet =
                PrivateWallet.GetPublicWalletAtSpecificDerivationPath(masterPrivateKey, "m/84'/0'/8'");

            // When
            var derivedPublicKey = publicWallet.GetPublicKey(20);
            var expectedDerivedPublicKey = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToExtendedPublicKey()
                .ToChildExtendedPublicKey(20)
                .GetPublicKey();

            // Then
            Assert.Equal(expectedDerivedPublicKey, derivedPublicKey);
        }

        [Fact]
        public void ExtendedPrivateKey_ExtendedPublicKey_PublicKey_CompareTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();

            // When
            var derivedPublicKey = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToExtendedPublicKey()
                .ToChildExtendedPublicKey(20)
                .ToChildExtendedPublicKey(0)
                .GetPublicKey();

            var expectedDerivedPublicKey = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToChildExtendedPrivateKey(20)
                .ToChildExtendedPrivateKey(0)
                .GetPublicKey();

            // Then
            Assert.Equal(expectedDerivedPublicKey, derivedPublicKey);
        }
        
        [Fact]
        public void Mnemonic_ExtendedPrivateKey_ExtendedPublicKey_PublicKey_CompareTest()
        {
            // Given
            var mnemonicPhrase = "cabin alert minute verb sing accuse chest pause scatter jealous bronze cruise phrase bench senior cube march job left pencil short glide hat sketch";
            var mnemonic = new Xcb.Net.BIP39.Mnemonic24(mnemonicPhrase);
            var masterPrivateKey = mnemonic.ToExtendedPrivateKey();

            // When
            var derivedPublicKey = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToExtendedPublicKey()
                .ToChildExtendedPublicKey(20)
                .ToChildExtendedPublicKey(0)
                .GetPublicKey();

            var expectedDerivedPublicKey = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToChildExtendedPrivateKey(20)
                .ToChildExtendedPrivateKey(0)
                .GetPublicKey();

            // Then
            Assert.Equal(expectedDerivedPublicKey, derivedPublicKey);
        }
        
        [Fact]
        public void ExtendedPrivateKey_ExtendedPublicKey_Address_CompareTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();

            // When
            var derivedAddress = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToExtendedPublicKey()
                .ToChildExtendedPublicKey(20)
                .ToChildExtendedPublicKey(0)
                .GetAddress(3);

            var expectedAddress = masterPrivateKey.ToChildExtendedPrivateKey(0x80000000 + 84)
                .ToChildExtendedPrivateKey(0x80000000 + 0)
                .ToChildExtendedPrivateKey(0x80000000 + 8)
                .ToChildExtendedPrivateKey(20)
                .ToChildExtendedPrivateKey(0)
                .GetAddress(3);

            // Then
            Assert.Equal(expectedAddress, derivedAddress);
        }

        [Fact]
        public void PrivateWallet_PublicWallet_PublicKey_ComareTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();
            var derivationPath = "m/84'/0'/8'/0";
            
            // When
            var privateWallet =
                PrivateWallet.GetPrivateWalletAtSpecificDerivationPath(masterPrivateKey, derivationPath);
            var expectedPublicKey = privateWallet.GetPublicKey();
            
            var publicWallet =
                PrivateWallet.GetPublicWalletAtSpecificDerivationPath(masterPrivateKey, derivationPath);
            var derivedPublicKey = publicWallet.GetPublicKey();

            //Then
            Assert.Equal(expectedPublicKey,derivedPublicKey);
        }
        
        [Fact]
        public void PrivateWallet_DerivedPublicWallet_Address_ComareTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();
            var networkId = 3;
            
            // When
            var privateWallet =
                PrivateWallet.GetPrivateWalletAtSpecificDerivationPath(masterPrivateKey, "m/84'/0'/8'");
            var expectedAddress = privateWallet.GetAddress(networkId,"20/0");

            var publicWallet = privateWallet.DerivePublicWallet("");
            var derivedAddress = publicWallet.GetAddress(networkId,"20/0");

            //Then
            Assert.Equal(expectedAddress,derivedAddress);
        }
        
        [Fact]
        public void RootPrivateWallet_DerivedPublicWallet_Address_ComareTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();
            var derivationPath = "m/84'/0'/8'/";
            var networkId = 3;
            
            // When
            var rootPrivateWallet = new PrivateWallet(masterPrivateKey);
            var expectedAddress = rootPrivateWallet.GetXcbECKey(networkId,derivationPath + "20/0").GetAddress();

            var publicWallet = rootPrivateWallet.DerivePublicWallet(derivationPath);
            var derivedAddress = publicWallet.GetAddress(networkId,"20/0");

            //Then
            Assert.Equal(expectedAddress,derivedAddress);
        }
        
        [Fact]
        public void PrivateWallet_DerivedPublicWallet_Wif_Address_ComareTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();
            var networkId = 3;
            
            // When
            var privateWallet =
                PrivateWallet.GetPrivateWalletAtSpecificDerivationPath(masterPrivateKey, "m/84'/0'/8'");
            var expectedAddress = privateWallet.GetAddress(networkId,"20/0");

            var wif = privateWallet.GetExtendedPublicKey();
            var publicWallet = new PublicWallet(wif);
            var derivedAddress = publicWallet.GetAddress(networkId,"20/0");

            //Then
            Assert.Equal(expectedAddress,derivedAddress);
        }
        
        [Fact]
        public void PrivateWallet_DerivedPublicWallet_Wif_XCBECKey_Address_ComareTest()
        {
            // Given
            var masterPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();
            var networkId = 3;
            
            // When
            var privateWallet =
                PrivateWallet.GetPrivateWalletAtSpecificDerivationPath(masterPrivateKey, "m/84'/0'/8'");
            var expectedAddress = privateWallet.GetXcbECKey(networkId, "20/0").GetAddress();

            var wif = privateWallet.GetExtendedPublicKey();
            var publicWallet = new PublicWallet(wif);
            var derivedAddress = publicWallet.GetAddress(networkId,"20/0");

            //Then
            Assert.Equal(expectedAddress,derivedAddress);
        }

        [Fact]
        public void RootPrivateWallet_DerivedPublicKeyWallet_Wif_Address_CompareTest2()
        {
            var mnemonicPhrase = "cabin alert minute verb sing accuse chest pause scatter jealous bronze cruise phrase bench senior cube march job left pencil short glide hat sketch";
            var mnemonic = new Xcb.Net.BIP39.Mnemonic24(mnemonicPhrase);
            var masterPrivateKey = mnemonic.ToExtendedPrivateKey();
            var derivationBase = "m/44'/654'/0'/";
            
            
            var rootWallet = new PrivateWallet(masterPrivateKey);
            var addressFromPrivate = rootWallet.GetXcbECKey(3, derivationBase + "221/0").GetAddress();

            
            var wif = rootWallet.DerivePublicWallet(derivationBase).GetExtendedPublicKey();

            var addressFromPublic = new PublicWallet(wif).GetAddress(3, "221/0");


            // Then
            Assert.Equal(addressFromPublic, addressFromPrivate);
        }
    }
}