using System;

namespace Org.BouncyCastle.Extended.OpenSsl
{
	public interface IPasswordFinder
	{
		char[] GetPassword();
	}
}
