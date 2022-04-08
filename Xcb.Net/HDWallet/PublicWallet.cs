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

        public override string GetAddress(int networkId, params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(index);

            var derivedPublicKey = this.DerivePath<ExtendedPublicKey>(derivationPath);

            return derivedPublicKey.GetAddress(networkId);
        }

        public override byte[] GetPublicKey(params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(index);

            var derivedPublicKey = this.DerivePath<ExtendedPublicKey>(derivationPath);

            return derivedPublicKey.GetPublicKey();
        }



        public override byte[] GetPublicKey(string childDerviationPath)
        {
            throw new System.NotImplementedException();
        }

        public override string GetAddress(int networkId, string childDerivaitonPath)
        {
            throw new System.NotImplementedException();
        }

        protected override ExtendedKeyBase Derive(ExtendedKeyBase extKey, uint index)
        {
            var extPubKey = extKey as ExtendedPublicKey;
            return extPubKey.ToChildExtendedPublicKey(index);
        }
    }
}