using Xcb.Net.ABI.Decoders;
using Xcb.Net.ABI.Encoders;

namespace Xcb.Net.ABI
{
    public class BytesElementaryType : ABIType
    {
        public BytesElementaryType(string name, int size) : base(name)
        {
            Decoder = new BytesElementaryTypeDecoder(size);
            Encoder = new BytesElementaryTypeEncoder(size);
        }
    }
}