using System;
using System.Collections.Generic;
using System.Text;

namespace Xcb.Net.HDWallet
{
    public abstract class WalletBase
    {
        private readonly ExtendedKeyBase _masterExtendedKey;

        public WalletBase(ExtendedKeyBase extendedKey)
        {
            _masterExtendedKey = extendedKey;
        }
        public abstract byte[] GetPublicKey(params int[] index);

        public abstract string[] GetAddress(int networkId, params int[] index);

        protected abstract ExtendedKeyBase Derive(ExtendedKeyBase extKey, int index);

        protected K DerivePath<K>(string path) where K : ExtendedKeyBase
        {
            ValidateDerivationPath(path);

            Queue<string> pathQueue = new Queue<string>(path.Split('/'));

            ExtendedKeyBase key = _masterExtendedKey;

            _ = pathQueue.Dequeue() switch
            {
                "m" => "m",
                _ => throw new ArgumentException("Invalid Derivation Path")
            };

            while (pathQueue.Count != 0)
            {
                if (!int.TryParse(pathQueue.Dequeue().Replace("'", ""), out int index))
                {
                    throw new ArgumentException("Invalid Derivation Path number format");
                }

                key = Derive(key, index);
            }

            return (K)key;

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