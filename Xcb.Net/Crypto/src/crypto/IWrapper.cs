using System;

using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto
{
    public interface IWrapper
    {
		/// <summary>The name of the algorithm this cipher implements.</summary>
		string AlgorithmName { get; }

		void Init(bool forWrapping, ICipherParameters parameters);

		byte[] Wrap(byte[] input, int inOff, int length);

        byte[] Unwrap(byte[] input, int inOff, int length);
    }
}
