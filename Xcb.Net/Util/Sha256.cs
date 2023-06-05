using System.Linq;
using System.Text;
using Xcb.Net.Extensions;

namespace Xcb.Net.Util
{
    public class Sha256
    {
        public static Sha256 Current { get; } = new Sha256();
        public string CalculateHash(string value)
        {
            var input = Encoding.UTF8.GetBytes(value);
            var output = CalculateHash(input);
            return output.ToHex();
        }

        public string CalculateHashFromHex(params string[] hexValues)
        {
            var joinedHex = string.Join("", hexValues.Select(x => x.RemoveHexPrefix()).ToArray());
            return CalculateHash(joinedHex.HexToByteArray()).ToHex();
        }

        public byte[] CalculateHash(byte[] value)
        {
            var digest = new Org.BouncyCastle.Extended.Crypto.Digests.Sha256Digest();
            var output = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(value, 0, value.Length);
            digest.DoFinal(output, 0);
            return output;
        }
        
    }
}
