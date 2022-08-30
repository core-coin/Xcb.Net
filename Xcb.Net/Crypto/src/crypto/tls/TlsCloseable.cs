using System;
using System.IO;

namespace Org.BouncyCastle.Extended.Crypto.Tls
{
    public interface TlsCloseable
    {
        /// <exception cref="IOException"/>
        void Close();
    }
}
