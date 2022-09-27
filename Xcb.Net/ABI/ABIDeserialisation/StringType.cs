using Xcb.Net.ABI.Decoders;
using Xcb.Net.ABI.Encoders;

namespace Xcb.Net.ABI
{
    public class StringType : ABIType
    {
        public StringType() : base("string")
        {
            Decoder = new StringTypeDecoder();
            Encoder = new StringTypeEncoder();
        }

        public override int FixedSize => -1;
    }
}