using System;
using Xcb.Net.Extensions;
using Nethereum.Util;

namespace Nethereum.ABI.Decoders
{
    public class AddressTypeDecoder : TypeDecoder
    {
        private IntTypeDecoder _intTypeDecoder;

        public AddressTypeDecoder()
        {
            _intTypeDecoder = new IntTypeDecoder();
        }

        public override object Decode(byte[] encoded, Type type)
        {
            if (!IsSupportedType(type)) throw new NotSupportedException(type + " is not supported");
            var output = new byte[22];
            Array.Copy(encoded, 10, output, 0, 22);
            return output.ToHex();
        }

        public override Type GetDefaultDecodingType()
        {
            return typeof(string);
        }

        public override bool IsSupportedType(Type type)
        {
            return type == typeof(string) || type == typeof(object);
        }
    }
}