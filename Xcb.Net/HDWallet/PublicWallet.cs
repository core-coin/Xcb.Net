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

        public PublicWallet DerivePublicWallet(string derivationPath)
        {
            var derivedKey = DerivePath<ExtendedPublicKey>(derivationPath);
            return new PublicWallet(derivedKey, RootDerivationPath + derivationPath);
        }

        private string GetTargetDerivationPath(params uint[] index)
        {
            var postfix = string.Join("/", index);
            return postfix;
        }

        public override string GetAddress(int networkId, string childDerivaitonPath)
        {
            var derivedPublicKey = this.DerivePath<ExtendedPublicKey>(childDerivaitonPath);

            return derivedPublicKey.GetAddress(networkId);
        }

        public override string GetAddress(int networkId, params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(index);

            return GetAddress(networkId, derivationPath);
        }

        public override byte[] GetPublicKey(params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(index);

            return GetPublicKey(derivationPath);
        }



        public override byte[] GetPublicKey(string childDerviationPath)
        {
            var derivedPublicKey = this.DerivePath<ExtendedPublicKey>(childDerviationPath);

            return derivedPublicKey.GetPublicKey();
        }



        protected override ExtendedKeyBase Derive(ExtendedKeyBase extKey, uint index)
        {
            var extPubKey = extKey as ExtendedPublicKey;
            return extPubKey.ToChildExtendedPublicKey(index);
        }
    }
}