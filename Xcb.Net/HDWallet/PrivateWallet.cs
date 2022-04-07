using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Xcb.Net.Signer;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Xcb.Net.HDWallet
{
    public class PrivateWallet : WalletBase
    {
        public PrivateWallet(ExtendedPrivateKey master, string derivationPath) : base(master, derivationPath)
        {
        }

        public PrivateWallet(ExtendedPrivateKey master) : base(master) { }

        public override string GetAddress(int networkId, params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(_derivationPath, index);

            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(derivationPath);

            return derivedPrivateKey.GetAddress(networkId);
        }

        public override byte[] GetPublicKey(params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(_derivationPath, index);

            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(derivationPath);

            return derivedPrivateKey.GetPublicKey();
        }

        public byte[] GetPrivateKey(params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(_derivationPath, index);

            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(derivationPath);

            return derivedPrivateKey.GetPrivateKey();
        }

        public XcbECKey GetXcbECKey(int networkId, params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(_derivationPath, index);

            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(derivationPath);

            return derivedPrivateKey.ToXcbECKey(networkId);
        }

        protected override ExtendedKeyBase Derive(ExtendedKeyBase extKey, uint index)
        {
            var extPubKey = extKey as ExtendedPrivateKey;
            return extPubKey.ToChildExtendedPrivateKey(index);
        }
    }
}