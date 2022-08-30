using System;

using Org.BouncyCastle.Extended.Math;

namespace Org.BouncyCastle.Extended.Crypto
{
    /// <summary>
    /// An "extended" interface for classes implementing DSA-style algorithms, that provides access
    /// to the group order.
    /// </summary>
    public interface IDsaExt
        : IDsa
    {
        /// <summary>The order of the group that the r, s values in signatures belong to.</summary>
        BigInteger Order { get; }
    }
}
