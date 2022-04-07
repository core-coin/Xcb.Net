using System;
using System.Collections.Generic;
using Xcb.Net.Signer;
using Xcb.Net.Extensions;
using Org.BouncyCastle.Security;
using Xcb.Net.RLP;
using System.Numerics;

namespace Xcb.Net.DWallet
{
    public class Wallet
    {
        public static readonly int MIN_MASTER_SEED_LENGTH = 256;
        public Dictionary<string, XcbECKey> xcbKeys { get; set; }

        private byte[] _masterSeed;

        private int _networkId;

        public Wallet(byte[] masterSeed, int networkId = 1)
        {
            if (masterSeed == null)
                throw new ArgumentNullException(nameof(masterSeed));

            if (masterSeed.Length < (MIN_MASTER_SEED_LENGTH / 8))
                throw new ArgumentException($"master seed must be at least {MIN_MASTER_SEED_LENGTH} bits");

            _masterSeed = masterSeed;
            _networkId = networkId;
        }

        public Wallet(string masterSeed, int networkId = 1) : this(masterSeed.HexToByteArray(), networkId)
        { }

        public XcbECKey GetXcbKey(byte[] userIndex, byte[] walletIndex)
        {
            var seedPostfix = RLP.RLP.EncodeElementsAndList(userIndex, walletIndex);
            byte[] seed = new byte[_masterSeed.Length + seedPostfix.Length];

            Array.Copy(_masterSeed, seed, _masterSeed.Length);
            Array.Copy(seedPostfix, 0, seed, _masterSeed.Length, seedPostfix.Length);

            XcbECKey key = XcbECKey.GenerateKey(_networkId);

            return key;
        }

        public XcbECKey GetXcbKey(long userIndex, long walletIndex)
        {
            return GetXcbKey(new BigInteger(userIndex).ToBytesForRLPEncoding(), new BigInteger(walletIndex).ToBytesForRLPEncoding());
        }

        public XcbECKey GetXcbKey(int userIndex, int walletIndex)
        {
            return GetXcbKey(new BigInteger(userIndex).ToBytesForRLPEncoding(), new BigInteger(walletIndex).ToBytesForRLPEncoding());
        }
    }
}
