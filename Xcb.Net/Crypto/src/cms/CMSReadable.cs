using System;
using System.IO;

namespace Org.BouncyCastle.Extended.Cms
{
	public interface CmsReadable
	{
		Stream GetInputStream();
	}
}
