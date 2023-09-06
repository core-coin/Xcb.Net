using System;
using System.Collections.Generic;
using System.Linq;

namespace Xcb.Net.HDWallet
{
    public abstract class WalletBase
    {
        public string RootDerivationPath { get; private set; }

        protected readonly ExtendedKeyBase _masterExtendedKey;

        public WalletBase(ExtendedKeyBase extendedKey, string derivationPath)
        {
            ValidateDerivationPath(derivationPath);
            RootDerivationPath = derivationPath;
            _masterExtendedKey = extendedKey ?? throw new ArgumentNullException(nameof(extendedKey));
        }


        public WalletBase(ExtendedKeyBase extendedKey) : this(extendedKey, "m")
        {

        }

        public abstract byte[] GetPublicKey(params uint[] index);

        public abstract byte[] GetPublicKey(string childDerviationPath);

        public abstract string GetAddress(int networkId, params uint[] index);

        public abstract string GetAddress(int networkId, string childDerivaitonPath);

        protected abstract ExtendedKeyBase Derive(ExtendedKeyBase extKey, uint index);

        protected K DerivePath<K>(string derivationpath) where K : ExtendedKeyBase
        {
            return GetKeyAtDerivePath<K>((K)_masterExtendedKey, derivationpath, this.Derive);
        }
        protected static K GetKeyAtDerivePath<K>(K masertKey, string derivationpath, Func<ExtendedKeyBase, uint, ExtendedKeyBase> derive) where K : ExtendedKeyBase
        {
            Queue<string> pathQueue = new Queue<string>(derivationpath.Split('/', StringSplitOptions.RemoveEmptyEntries));

            K key = masertKey;

            while (pathQueue.Count != 0)
            {
                var indexStr = pathQueue.Dequeue();
                if (indexStr == "m")
                    continue;

                bool hardened = indexStr.EndsWith("'");

                if (!uint.TryParse(indexStr.Replace("'", ""), out uint index))
                {
                    throw new ArgumentException("Invalid Derivation Path number format");
                }

                if (hardened)
                    index += 0x80000000;

                key = (K)derive((K)key, index);
            }

            return (K)key;
        }

        private void ValidateDerivationPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Empty path", nameof(path));

            if (!path.StartsWith("m"))
                throw new ArgumentException("Invalid Derivation Path, {0} should start with m/", nameof(path));
        }
    }
}