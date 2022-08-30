using System;

namespace Org.BouncyCastle.Extended.Cms
{
	internal interface IDigestCalculator
	{
		byte[] GetDigest();
	}
}
