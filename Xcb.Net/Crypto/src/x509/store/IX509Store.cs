using System;
using System.Collections;

namespace Org.BouncyCastle.Extended.X509.Store
{
	public interface IX509Store
	{
//		void Init(IX509StoreParameters parameters);
		ICollection GetMatches(IX509Selector selector);
	}
}
