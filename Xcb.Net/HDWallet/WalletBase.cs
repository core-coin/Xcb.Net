using System;
using System.Collections.Generic;
using System.Linq;

namespace Xcb.Net.HDWallet
{
    public abstract class WalletBase
    {
        protected readonly string _derivationPath;
        protected readonly ExtendedKeyBase _masterExtendedKey;

        public WalletBase(ExtendedKeyBase extendedKey, string derivationPath)
        {
            ValidateDerivationPath(derivationPath);
            _derivationPath = derivationPath;
            _masterExtendedKey = extendedKey ?? throw new ArgumentNullException(nameof(extendedKey));
        }


        public WalletBase(ExtendedKeyBase extendedKey) : this(extendedKey, "m/44'/0'/0'")
        {

        }

        public abstract byte[] GetPublicKey(params uint[] index);

        public abstract string GetAddress(int networkId, params uint[] index);

        protected abstract ExtendedKeyBase Derive(ExtendedKeyBase extKey, uint index);

        protected K DerivePath<K>(string path) where K : ExtendedKeyBase
        {
            Queue<string> pathQueue = new Queue<string>(path.Split('/'));

            ExtendedKeyBase key = _masterExtendedKey;

            _ = pathQueue.Dequeue() switch
            {
                "m" => "m",
                _ => throw new ArgumentException("Invalid Derivation Path")
            };

            while (pathQueue.Count != 0)
            {
                if (!uint.TryParse(pathQueue.Dequeue().Replace("'", ""), out uint index))
                {
                    throw new ArgumentException("Invalid Derivation Path number format");
                }

                key = Derive(key, index);
            }

            return (K)key;
        }

        protected string GetTargetDerivationPath(string derivationPath, params uint[] index)
        {
            var postfix = string.Join("/", index.Select(a => a + "'"));
            return derivationPath + "/" + postfix;
        }

        private void ValidateDerivationPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Empty path", nameof(path));

            if (!path.StartsWith("m/"))
                throw new ArgumentException("Invalid Derivation Path, {0} should start with m/", nameof(path));
        }
    }
}