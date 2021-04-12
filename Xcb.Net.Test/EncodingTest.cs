using System.Text;
using Xcb.Net.Extensions;
using Xunit;
using Xcb.Net.RLP;
using System.Numerics;

namespace Xcb.Net.Test
{
    public class EncodingTest
    {
        [Fact]
        public void SimpleData()
        {
            //Given
            var helloBytes = Encoding.UTF8.GetBytes("hello");
            var data = new byte[][] { helloBytes };

            //When
            var encoded = RLP.RLP.EncodeElement(helloBytes);
            var encodedHex = encoded.ToHex();
            System.Console.WriteLine(encodedHex);
            //Then
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
    }
}