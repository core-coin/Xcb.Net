﻿namespace Xcb.Net.ABI.Encoders
{
    public interface ITypeEncoder
    {
        byte[] Encode(object value);
        byte[] EncodePacked(object value);
    }
}