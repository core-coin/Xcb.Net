namespace Xcb.Net.HDWallet
{
    public class PublicWallet : WalletBase
    {
        public PublicWallet(ExtendedPublicKey master) : base(master)
        {
        }

        public PublicWallet(ExtendedPublicKey master, string derivationPath) : base(master, derivationPath)
        {

        }

        public override string GetAddress(int networkId, params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(_derivationPath, index);

            var derivedPublicKey = this.DerivePath<ExtendedPublicKey>(derivationPath);

            return derivedPublicKey.GetAddress(networkId);
        }

        public override byte[] GetPublicKey(params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(_derivationPath, index);

            var derivedPublicKey = this.DerivePath<ExtendedPublicKey>(derivationPath);

            return derivedPublicKey.GetPublicKey();
        }

        protected override ExtendedKeyBase Derive(ExtendedKeyBase extKey, uint index)
        {
            var extPubKey = extKey as ExtendedPublicKey;
            return extPubKey.ToChildExtendedPublicKey(index);
        }
    }
}