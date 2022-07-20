using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Xcb.Net.Signer;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Xcb.Net.HDWallet
{
    public class PrivateWallet : WalletBase
    {
        public PrivateWallet(ExtendedPrivateKey master) : base(master) { }
        public PrivateWallet(ExtendedPrivateKey master, string derivationPath) : base(master, derivationPath)
        {
        }

        public static PrivateWallet GetPrivateWalletAtSpecificDerivationPath(ExtendedPrivateKey master, string derivationPath)
        {
            var derivedKey = GetKeyAtDerivePath<ExtendedPrivateKey>(master, derivationPath, DeriveKey);
            return new PrivateWallet(derivedKey, derivationPath);
        }

        public static PublicWallet GetPublicWalletAtSpecificDerivationPath(ExtendedPrivateKey master, string derivationPath)
        {
            var derivedKey = GetKeyAtDerivePath<ExtendedPrivateKey>(master, derivationPath, DeriveKey).ToExtendedPublicKey();
            return new PublicWallet(derivedKey, derivationPath);
        }

        public PublicWallet DerivePublicWallet(string derivationPath)
        {
            var derivedKey = DerivePath<ExtendedPrivateKey>(derivationPath);
            return new PublicWallet(derivedKey.ToExtendedPublicKey(), RootDerivationPath + derivationPath);
        }

        public PrivateWallet DerivePrivateWallet(string derivationPath)
        {
            var derivedKey = DerivePath<ExtendedPrivateKey>(derivationPath);
            return new PrivateWallet(derivedKey, RootDerivationPath + derivationPath);
        }

        private string GetTargetDerivationPath(string derivationPath, params uint[] index)
        {
            var postfix = string.Join("/", index);
            if (!string.IsNullOrEmpty(derivationPath))
                derivationPath += "/";
            return derivationPath + postfix;
        }


        public override string GetAddress(int networkId, params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(null, index);

            return GetAddress(networkId, derivationPath);
        }

        public override string GetAddress(int networkId, string childDerivaitonPath)
        {
            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(childDerivaitonPath);

            return derivedPrivateKey.GetAddress(networkId);
        }

        public override byte[] GetPublicKey(params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(null, index);

            return GetPublicKey(derivationPath);
        }

        public override byte[] GetPublicKey(string childDerivationPath)
        {
            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(childDerivationPath);

            return derivedPrivateKey.GetPublicKey();
        }

        public ExtendedPublicKey GetExtendedPublicKey()
        {
            var extendedPrivateKey = (ExtendedPrivateKey)_masterExtendedKey;
            return extendedPrivateKey.ToExtendedPublicKey();
        }

        public ExtendedPrivateKey GetExtendedPrivateKey()
        {
            var extendedPrivateKey = (ExtendedPrivateKey)_masterExtendedKey;
            return extendedPrivateKey;
        }

        public byte[] GetPrivateKey(params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(null, index);

            return GetPrivateKey(derivationPath);
        }

        public byte[] GetPrivateKey(string derivationPath)
        {
            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(derivationPath);

            return derivedPrivateKey.GetPrivateKey();
        }

        public XcbECKey GetXcbECKey(int networkId, params uint[] index)
        {
            var derivationPath = GetTargetDerivationPath(null, index);

            return GetXcbECKey(networkId, derivationPath);
        }

        public XcbECKey GetXcbECKey(int networkId, string derivationPath)
        {
            var derivedPrivateKey = this.DerivePath<ExtendedPrivateKey>(derivationPath);

            return derivedPrivateKey.ToXcbECKey(networkId);
        }

        protected override ExtendedKeyBase Derive(ExtendedKeyBase extKey, uint index)
        {
            var extPriKey = extKey as ExtendedPrivateKey;

            return PrivateWallet.DeriveKey(extPriKey, index);
        }

        private static ExtendedKeyBase DeriveKey(ExtendedKeyBase extKey, uint index)
        {
            var extPriKey = extKey as ExtendedPrivateKey;

            return extPriKey.ToChildExtendedPrivateKey(index);
        }
    }
}