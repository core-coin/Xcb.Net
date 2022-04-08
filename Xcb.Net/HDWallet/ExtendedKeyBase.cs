using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xcb.Net.Signer;

namespace Xcb.Net.HDWallet
{
    public abstract class ExtendedKeyBase
    {
        private readonly byte[] _data;

        protected ExtendedKeyBase(byte[] data)
        {
            if (data?.Length != 114)
                throw new ArgumentException("data must be 114 bytes in length", nameof(data));

            _data = data;
        }
        public static implicit operator byte[](ExtendedKeyBase d) => d._data;

        public abstract byte[] GetPublicKey();

        public abstract string GetAddress(int networkId);

        private static byte[] Pbkdf2Sha3512(byte[] password, byte[] salt, int iterations, int hashByteSize)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512));
            pdb.Init(password, salt,
                         iterations);
            var key = (KeyParameter)pdb.GenerateDerivedMacParameters(hashByteSize * 8);
            return key.GetKey();
        }

        public static byte[] Pbkdf2(byte[] password, byte[] salt)
        {
            return Pbkdf2Sha3512(password, salt, 2048, 57);
        }

        public static byte[] ConcatenateAndHex(byte prefix, byte[] password, uint index, byte[] salt)
        {
            byte[] result = new byte[62];
            result[0] = prefix;
            Array.Copy(password, 0, result, 1, 57);
            for (int i = 58; i < 62; i++)
            {
                result[i] = (byte)(index & 0xff);
                index >>= 8;
            }
            return Pbkdf2(result, salt);
        }

        public static void ReduceKey(byte[] key)
        {
            key[56] = 0;
            key[55] = 0;
            key[54] = 0;
            key[53] = 0;
            key[0] &= 0xfc;
        }

        public static byte[] AddTwoSecrets(byte[] key1, byte[] key2)
        {
            byte[] key = new byte[57];
            uint count = 0;
            for (int i = 0; i < 57; i++)
            {
                count += (uint)(key1[i]) + (uint)(key2[i]);
                key[i] = (byte)(count & 0xff);
                count >>= 8;
            }
            return key;
        }
    }
}