using Xcb.Net.ABI.Decoders;
using Xcb.Net.ABI.Encoders;

namespace Xcb.Net.ABI
{
    public class BytesType : ABIType
    {
        public BytesType() : base("bytes")
        {
            Decoder = new BytesTypeDecoder();
            Encoder = new BytesTypeEncoder();
        }

        public override int FixedSize => -1;
    }
}