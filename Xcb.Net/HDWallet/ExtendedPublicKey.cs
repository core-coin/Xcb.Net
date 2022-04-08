using System;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xcb.Net.Extensions;
using Xcb.Net.Signer;

namespace Xcb.Net.HDWallet
{
    public class ExtendedPublicKey : ExtendedKeyBase
    {
        public ExtendedPublicKey(byte[] data) : base(data)
        {

        }

        public static explicit operator ExtendedPublicKey(byte[] b) => new ExtendedPublicKey(b);

        public ExtendedPublicKey ToChildExtendedPublicKey(uint index)
        {
            byte[] extendedPublicKey = this;
            byte[] child = new byte[114];
            byte[] chain = new byte[57];

            Array.Copy(extendedPublicKey, 0, chain, 0, 57);

            byte[] pub = new byte[57];

            Array.Copy(extendedPublicKey, 57, pub, 0, 57);

            byte[] result = new byte[57];

            if (index >= 0x80000000)
            {
                throw new Exception("Cant retrieve public key from hardened parent key");
            }
            else
            {
                var hex = ConcatenateAndHex(3, pub, index, chain);
                Array.Copy(hex, 0, child, 0, 57);
                hex = ConcatenateAndHex(2, pub, index, chain);
                ReduceKey(hex);
                Ed448.ShiftPublic(pub, hex, result);
                Array.Copy(result, 0, child, 57, 57);
            }
            return (ExtendedPublicKey)child;
        }

        public override byte[] GetPublicKey()
        {
            var bytes = (byte[])this;
            return bytes[57..114];
        }

        public override string GetAddress(int networkId)
        {
            return XcbECKey.GetAddressFromPublicKey(GetPublicKey(), networkId);
        }
    }
}