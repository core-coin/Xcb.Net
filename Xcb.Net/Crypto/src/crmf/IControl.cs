using System;

using Org.BouncyCastle.Extended.Asn1;

namespace Org.BouncyCastle.Extended.Crmf
{
    /// <summary>
    /// Generic interface for a CertificateRequestMessage control value.
    /// </summary>
    public interface IControl
    {
        /// <summary>
        /// Return the type of this control.
        /// </summary>
        DerObjectIdentifier Type { get; }

        /// <summary>
        /// Return the value contained in this control object.
        /// </summary>
        Asn1Encodable Value { get; }
    }
}
