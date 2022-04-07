using System;
using Xcb.Net.Signer;

namespace Xcb.Net.HDWallet
{
    public class ExtendedPrivateKey : ExtendedKey
    {
        public ExtendedPrivateKey(byte[] data) : base(data)
        {

        }

        public static explicit operator ExtendedPrivateKey(byte[] b) => new ExtendedPrivateKey(b);

        public static ExtendedPrivateKey SeedToMaster(byte[] seed)
        {
            if (seed.Length != 64)
            {
                throw new Exception("Length of seed must be 64");
            }

            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();

            byte[] part1 = Pbkdf2(seed, enc.GetBytes("mnemonicforthechain"));
            byte[] part2 = Pbkdf2(seed, enc.GetBytes("mnemonicforthekey"));
            byte[] result = new byte[114];
            Array.Copy(part1, 0, result, 0, 57);
            Array.Copy(part2, 0, result, 57, 57);
            result[113] |= 0x80;
            result[112] |= 0x80;
            result[112] &= 0xbf;
            return (ExtendedPrivateKey)result;
        }

        public ExtendedPublicKey ToExtendedPublicKey()
        {
            byte[] extendedPrivateKey = this;
            byte[] privateKey = new byte[57];

            Array.Copy(extendedPrivateKey, 57, privateKey, 0, 57);

            var key = new XcbECKey(privateKey, 1);
            var pub = key.GetPublicKeyBytes();
            byte[] extendedPublic = new byte[114];

            Array.Copy(extendedPrivateKey, 0, extendedPublic, 0, 57);
            Array.Copy(pub, 0, extendedPublic, 57, 57);

            return (ExtendedPublicKey)extendedPublic;
        }

        public ExtendedPrivateKey ToChildExtendedPrivateKey(uint index)
        {
            byte[] extendedPrivateKey = this;
            byte[] child = new byte[114];
            byte[] chain = new byte[57];

            Array.Copy(extendedPrivateKey, 0, chain, 0, 57);

            byte[] priv = new byte[57];

            Array.Copy(extendedPrivateKey, 57, priv, 0, 57);

            var key = new XcbECKey(priv, 1);
            var pub = key.GetPublicKeyBytes();

            var hex = index >= 0x80000000 ? ConcatenateAndHex(1, priv, index, chain) :
                                            ConcatenateAndHex(3, pub, index, chain);

            Array.Copy(hex, 0, child, 0, 57);

            hex = index >= 0x80000000 ? ConcatenateAndHex(0, priv, index, chain) :
                                        ConcatenateAndHex(2, pub, index, chain);

            ReduceKey(hex);
            var a = AddTwoSecrets(priv, hex);
            Array.Copy(a, 0, child, 57, 57);

            return (ExtendedPrivateKey)child;
        }

        public XcbECKey ToXcbECKey(int networkId)
        {
            var key = new XcbECKey(((byte[])this)[57..114], networkId);
            return key;
        }

        public override byte[] GetPublicKey()
        {
            return ToXcbECKey(1).GetPrivateKeyBytes();
        }

        public override string GetAddress(int networkId)
        {
            return ToXcbECKey(networkId).GetAddress();
        }
    }
}