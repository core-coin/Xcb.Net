using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Xcb.Net.Signer;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Xcb.Net.HDWallet
{
    public class HDWallet
    {
        public byte[] pbkdf2_sha3_256(byte[] password, byte[] salt, int iterations, int hashByteSize)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512));
            pdb.Init(password, salt,
                         iterations);
            var key = (KeyParameter)pdb.GenerateDerivedMacParameters(hashByteSize * 8);
            return key.GetKey();
        }

        public byte[] shaHash(byte[] password, byte[] salt)
        {
            return pbkdf2_sha3_256(password, salt, 2048, 57);
        }

        public byte[] concatenateAndHex(byte prefix, byte[] password, uint index, byte[] salt)
        {
            byte[] result = new byte[62];
            result[0] = prefix;
            Array.Copy(password, 0, result, 1, 57);
            for (int i = 58; i < 62; i++)
            {
                result[i] = (byte)(index & 0xff);
                index >>= 8;
            }
            return shaHash(result, salt);
        }

        public void reducePrivate(byte[] key)
        {
            key[56] = 0;
            key[55] = 0;
            key[54] = 0;
            key[53] = 0;
            key[0] &= 0xfc;
        }

        public byte[] addTwoSecrets(byte[] key1, byte[] key2)
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

        public byte[] seedToMaster(byte[] seed)
        {
            if (seed.Length != 64)
            {
                throw new Exception("Length of seed must be 64");
            }

            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();

            byte[] part1 = shaHash(seed, enc.GetBytes("mnemonicforthechain"));
            byte[] part2 = shaHash(seed, enc.GetBytes("mnemonicforthekey"));
            byte[] result = new byte[114];
            Array.Copy(part1, 0, result, 0, 57);
            Array.Copy(part2, 0, result, 57, 57);
            result[113] |= 0x80;
            result[112] |= 0x80;
            result[112] &= 0xbf;
            return result;
        }

        public byte[] extendedPrivateToPublic(byte[] extendedKey)
        {

            byte[] privateKey = new byte[57];
            Array.Copy(extendedKey, 57, privateKey, 0, 57);
            var key = new XcbECKey(privateKey, 1);
            var pub = key.GetPublicKeyBytes();
            byte[] extendedPublic = new byte[114];
            Array.Copy(extendedKey, 0, extendedPublic, 0, 57);
            Array.Copy(pub, 0, extendedPublic, 57, 57);
            return extendedPublic;
        }

        public byte[] childPrivateToPrivate(byte[] extPrivate, uint index)
        {

            byte[] child = new byte[114];
            byte[] chain = new byte[57];
            Array.Copy(extPrivate, 0, chain, 0, 57);
            byte[] priv = new byte[57];
            Array.Copy(extPrivate, 57, priv, 0, 57);
            var key = new XcbECKey(priv, 1);
            var pub = key.GetPublicKeyBytes();


            var hex = index >= 0x80000000 ? concatenateAndHex(1, priv, index, chain) :
                                            concatenateAndHex(3, pub, index, chain);
            Array.Copy(hex, 0, child, 0, 57);
            hex = index >= 0x80000000 ? concatenateAndHex(0, priv, index, chain) :
                                        concatenateAndHex(2, pub, index, chain);

            reducePrivate(hex);
            var a = addTwoSecrets(priv, hex);
            Array.Copy(a, 0, child, 57, 57);

            return child;
        }

        public byte[] childPublicToPublic(byte[] extPublic, uint index)
        {

            byte[] child = new byte[114];
            byte[] chain = new byte[57];
            Array.Copy(extPublic, 0, chain, 0, 57);
            byte[] pub = new byte[57];
            Array.Copy(extPublic, 57, pub, 0, 57);
            byte[] result = new byte[57];

            if (index >= 0x80000000)
            {
                throw new Exception("Cant retrieve public key from hardened parent key");
            }
            else
            {
                var hex = concatenateAndHex(3, pub, index, chain);
                Array.Copy(hex, 0, child, 0, 57);
                hex = concatenateAndHex(2, pub, index, chain);
                reducePrivate(hex);
                Ed448.ShiftPublic(pub, hex, result);
                Array.Copy(result, 0, child, 57, 57);
            }
            return child;
        }

    }
}