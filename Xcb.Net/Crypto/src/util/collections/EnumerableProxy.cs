using System;
using System.Collections;

namespace Org.BouncyCastle.Extended.Utilities.Collections
{
	public sealed class EnumerableProxy
		: IEnumerable
	{
		private readonly IEnumerable inner;

		public EnumerableProxy(
			IEnumerable inner)
		{
			if (inner == null)
				throw new ArgumentNullException("inner");

			this.inner = inner;
		}

		public IEnumerator GetEnumerator()
		{
			return inner.GetEnumerator();
		}
	}
}
