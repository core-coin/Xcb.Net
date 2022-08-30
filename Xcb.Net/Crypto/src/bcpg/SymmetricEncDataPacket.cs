using System;

namespace Org.BouncyCastle.Extended.Bcpg
{
	/// <remarks>Basic type for a symmetric key encrypted packet.</remarks>
    public class SymmetricEncDataPacket
        : InputStreamPacket
    {
        public SymmetricEncDataPacket(
            BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
        }
    }
}
