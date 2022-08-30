﻿using System;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    public abstract class NameType
    {
        /*
         * RFC 3546 3.1.
         */
        public const byte host_name = 0;

        public static bool IsValid(byte nameType)
        {
            return nameType == host_name;
        }
    }
}
