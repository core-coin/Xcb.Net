using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Xcb.Net.HDWallet;
using Xcb.Net.Util;

namespace Xcb.Net.BIP39
{
    public class Mnemonic24
    {
        const string INVALID_MNEMONIC = "INVALID MNEMONIC";
        private readonly string _words;
        private readonly string _passphrase;

        public Mnemonic24(string words, string passphrase = "")
        {
            _ = MnemonicToEntropy(words);
            _words = words;
            _passphrase = passphrase;
        }

        private static string ByteToBinaryString(byte b)
        {
            return Convert.ToString(b, 2);
        }

        private static string DecimalTo11LengthStringBinary(int decimalNumber)
        {
            return Convert.ToString(decimalNumber, 2).PadLeft(11, '0');
        }

        private static byte BinaryStringToByte(string str)
        {
            return Convert.ToByte(str, 2);
        }

        private byte DeriveCheckSumByte(byte[] entroyp)
        {
            var hash = Sha256.Current.CalculateHash(entroyp);
            var checksum = hash.First();

            return checksum;
        }

        byte[] MnemonicToEntropy(string mnemonic)
        {
            var words = mnemonic.Split(' ');

            if (words.Length != 24)
            {
                throw new ArgumentException(INVALID_MNEMONIC);
            }

            var wordList = WordList.ENGLISH_WORD_LIST;

            // convert word indices to 11 bit binary strings


            var bitsArray = words.Select(w =>
                {
                    var index = wordList.IndexOf(w);
                    if (index == -1)
                        throw new ArgumentException(INVALID_MNEMONIC);
                    return DecimalTo11LengthStringBinary(index);
                });

            var bits = string.Join("", bitsArray);


            var regex = new Regex(".{1,8}");

            var bytes = regex.Matches(bits)
                                .Select(a => a.Value)
                                .Select(a => BinaryStringToByte(a))
                                .ToArray();

            var entropyBytes = bytes.Take(32).ToArray();

            var checkusm = bytes[32];

            if (bytes.Length != 33)
                throw new ArgumentException(INVALID_MNEMONIC);

            var checksumByte = DeriveCheckSumByte(entropyBytes);


            if (checksumByte != checkusm)
                throw new ArgumentException(INVALID_MNEMONIC);

            return bytes;
        }

        private static byte[] PBKDF2(string mnemonic, string salt, int numBytes)
        {
            // Convert the salt to a byte array using UTF-8 encoding
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            // Use PBKDF2 with HMAC-SHA512 to derive the seed from the salt and mnemonic
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(mnemonic, saltBytes, 2048, HashAlgorithmName.SHA512);
            byte[] seed = pbkdf2.GetBytes(numBytes);

            return seed;
        }

        public ExtendedPrivateKey ToExtendedPrivateKey()
        {
            var mnemonic = _words + _passphrase;

            var seed1 = PBKDF2(mnemonic, "mnemonicforthekey", 57);
            var seed2 = PBKDF2(mnemonic, "mnemonicforthechain", 57);

            var seed = new byte[seed1.Length + seed2.Length];

            Array.Copy(seed1, seed, seed1.Length);
            Array.Copy(seed2, 0, seed, seed2.Length, seed2.Length);

            return new ExtendedPrivateKey(seed);
        }
    }
}