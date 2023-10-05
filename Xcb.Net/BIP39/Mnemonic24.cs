using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Extended.Security;
using Xcb.Net.HDWallet;
using Xcb.Net.Util;

namespace Xcb.Net.BIP39
{
    public class Mnemonic24
    {
        const string INVALID_MNEMONIC = "INVALID MNEMONIC";
        public string Words { get; }
        public string Passphrase { get; }

        private static readonly SecureRandom _secureRandom = new SecureRandom();

        public Mnemonic24(string words, string passphrase = "")
        {
            ValidateMnemonicWords(words);
            Words = words;
            Passphrase = passphrase;
        }

        public static Mnemonic24 GenerateMnemonic()
        {
            var randomEntropy = _secureRandom.GenerateSeed(32);

            var words = EntropyToMnemonic(randomEntropy);

            return new Mnemonic24(words);
        }

        private static string ByteToBinaryString(byte b)
        {
            return Convert.ToString(b, 2).PadLeft(8,'0');
        }

        private static string DecimalTo11LengthStringBinary(int decimalNumber)
        {
            return Convert.ToString(decimalNumber, 2).PadLeft(11, '0');
        }

        private static byte BinaryStringToByte(string str)
        {
            return Convert.ToByte(str, 2);
        }

        private static int BinaryStringToInteger(string str)
        {
            return Convert.ToInt32(str, 2);
        }

        private static byte DeriveCheckSumByte(byte[] entropy)
        {
            var hash = Sha256.Current.CalculateHash(entropy);
            var checksum = hash.First();

            return checksum;
        }

        private static string EntropyToMnemonic(byte[] entropy)
        {
            var checksum = DeriveCheckSumByte(entropy);

            var entropyWithChecksum = entropy.Append(checksum);

            var binaryString = string.Join("", entropyWithChecksum.Select(a => ByteToBinaryString(a)));

            var regex = new Regex(".{1,11}");

            var wordList = WordList.ENGLISH_WORD_LIST;

            var words = regex.Matches(binaryString)
                            .Select(a => a.Value)
                            .Select(a => BinaryStringToInteger(a))
                            .Select(a => wordList[a]);

            return string.Join(" ", words);
        }

        private static void ValidateMnemonicWords(string mnemonic)
        {
            var _ = MnemonicToEntropy(mnemonic);
        }

        private static byte[] MnemonicToEntropy(string mnemonic)
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
            return ExtendedKeyBase.Pbkdf2(Encoding.UTF8.GetBytes(mnemonic), Encoding.UTF8.GetBytes(salt));
        }

        public ExtendedPrivateKey ToExtendedPrivateKey()
        {
            var mnemonic = Words + Passphrase;

            var seed1 = PBKDF2(mnemonic, "mnemonicforthekey", 57);
            var seed2 = PBKDF2(mnemonic, "mnemonicforthechain", 57);

            var seed = new byte[seed1.Length + seed2.Length];

            Array.Copy(seed1, seed, seed1.Length);
            Array.Copy(seed2, 0, seed, seed2.Length, seed2.Length);

            seed[113] |= 0x80; // Set key type identifier
            seed[112] |= 0x80; // EdDSA standard
            seed[112] &= 0xbf; // Set to keep previous =1 during generation new accounts
            
            return new ExtendedPrivateKey(seed);
        }
    }
}