using System.Text;
using Xcb.Net.Extensions;
using Xunit;
using Xcb.Net.RLP;
using System.Numerics;

namespace Xcb.Net.Test
{
    public class EncodingTest
    {
        byte[][] emptyTransactionData;

        public EncodingTest()
        {
            emptyTransactionData = new byte[][]{
                BigInteger.Zero.ToBytesForRLPEncoding(),
                BigInteger.Zero.ToBytesForRLPEncoding(),
                BigInteger.Zero.ToBytesForRLPEncoding(),
                "cb08095e7baea6a6c7c4c2dfeb977efac326af552d87".HexToByteArray(),
                BigInteger.Zero.ToBytesForRLPEncoding(),
                "".ToBytesForRLPEncoding(),
                BigInteger.Zero.ToBytesForRLPEncoding(),
            };
        }


        [Fact]
        public void EmptyTrasnactionSigHashTest()
        {
            //Given
            var data = emptyTransactionData;

            //When
            byte[] encoded = RLP.RLP.EncodeElementsAndList(data);
            byte[] hash = Xcb.Net.Util.Sha3NIST.Current.CalculateHash(encoded);
            string hashHex = hash.ToHex(prefix: true);

            //Then
            Assert.Equal("0x0064d7a2aa08686b4f36a2188352ba162ff2b5bdce72335f4a0e25a6c5f47af7", hashHex);
        }

        [Theory]
        [InlineData("0", "0xc180")]
        [InlineData("1000", "0xc38203e8")]
        [InlineData("9000000000", "0xc6850218711a00")]
        public void BigIntegerRlpTest(string strNum, string expectedHex)
        {
            //Given
            BigInteger number = BigInteger.Parse(strNum);

            //When
            byte[] RlpEncoded = RLP.RLP.EncodeElementsAndList(number.ToBytesForRLPEncoding());

            string RplEncodedHex = RlpEncoded.ToHex(prefix: true);

            //Then
            Assert.Equal(expectedHex, RplEncodedHex);
        }

        [Theory]
        [InlineData("this is a string", "0xd19074686973206973206120737472696e67")]
        public void StringRlpTest(string str, string expectedHex)
        {
            //Given

            //When
            byte[] RlpEncoded = RLP.RLP.EncodeElementsAndList(str.ToBytesForRLPEncoding());

            string RplEncodedHex = RlpEncoded.ToHex(prefix: true);

            //Then
            Assert.Equal(expectedHex, RplEncodedHex);
        }

        [Theory]
        [InlineData("cb08095e7baea6a6c7c4c2dfeb977efac326af552d87", "0xd796cb08095e7baea6a6c7c4c2dfeb977efac326af552d87")]
        public void AddressRlpTest(string address, string expectedHex)
        {
            //Given
            byte[] addressBytes = address.HexToByteArray();

            //When
            byte[] RlpEncoded = RLP.RLP.EncodeElementsAndList(addressBytes);

            string RplEncodedHex = RlpEncoded.ToHex(prefix: true);

            //Then
            Assert.Equal(expectedHex, RplEncodedHex);
        }

        [Fact]
        public void EmptyBytesRlpTest()
        {
            //Given
            var emptyBytes = new byte[0];

            //When
            var rlpEncoded = RLP.RLP.EncodeElementsAndList(emptyBytes);
            var rlpEncodedHex = rlpEncoded.ToHex(true);

            //Then
            Assert.Equal("0xc180", rlpEncodedHex);
        }

    }
}
