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
            PrivateWallet privateWallet = new PrivateWallet(masterPrivateKey, "m/84'/0'/8'");

            // When
            var derivedPrivateKey = privateWallet.GetPrivateKey(20);
            var expectedDerivedPrivateKey = masterPrivateKey.ToChildExtendedPrivateKey(84)
                                                            .ToChildExtendedPrivateKey(0)
                                                            .ToChildExtendedPrivateKey(8)
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
            var masterPublicKey = masterPrivateKey.ToExtendedPublicKey();

            PublicWallet publicWallet = new PublicWallet(masterPublicKey, "m/84'/0'/8'");

            // When
            var derivedPublicKey = publicWallet.GetPublicKey(20);
            var expectedDerivedPublicKey = masterPublicKey.ToChildExtendedPublicKey(84)
                                                           .ToChildExtendedPublicKey(0)
                                                           .ToChildExtendedPublicKey(8)
                                                           .ToChildExtendedPublicKey(20)
                                                           .GetPublicKey();

            // Then
            Assert.Equal(expectedDerivedPublicKey, derivedPublicKey);
        }
    }
}