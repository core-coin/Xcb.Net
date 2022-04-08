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
            PrivateWallet privateWallet = PrivateWallet.GetPrivateWalletAtSpecificDerivationPath(masterPrivateKey, "m/84'/0'/8'");

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

            PublicWallet publicWallet = PrivateWallet.GetPublicWalletAtSpecificDerivationPath(masterPrivateKey, "m/84'/0'/8'");

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
    }
}