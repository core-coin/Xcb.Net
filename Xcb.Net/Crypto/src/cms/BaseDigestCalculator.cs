using System;

using Org.BouncyCastle.Extended.Utilities;

namespace Org.BouncyCastle.Extended.Cms
{
	internal class BaseDigestCalculator
		: IDigestCalculator
	{
		private readonly byte[] digest;

		internal BaseDigestCalculator(
			byte[] digest)
		{
			this.digest = digest;
		}

		public byte[] GetDigest()
		{
			return Arrays.Clone(digest);
		}
	}
}
