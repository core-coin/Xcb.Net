using System.IO;

using Org.BouncyCastle.Extended.Apache.Bzip2;
using Org.BouncyCastle.Extended.Utilities.Zlib;

namespace Org.BouncyCastle.Extended.Bcpg.OpenPgp
{
	/// <remarks>Compressed data objects</remarks>
    public class PgpCompressedData
		: PgpObject
    {
        private readonly CompressedDataPacket data;

		public PgpCompressedData(
            BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is CompressedDataPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.data = (CompressedDataPacket)packet;
        }

		/// <summary>The algorithm used for compression</summary>
        public CompressionAlgorithmTag Algorithm
        {
			get { return data.Algorithm; }
        }

		/// <summary>Get the raw input stream contained in the object.</summary>
        public Stream GetInputStream()
        {
            return data.GetInputStream();
        }

		/// <summary>Return an uncompressed input stream which allows reading of the compressed data.</summary>
        public Stream GetDataStream()
        {
            switch (Algorithm)
            {
				case CompressionAlgorithmTag.Uncompressed:
					return GetInputStream();
				case CompressionAlgorithmTag.Zip:
					return new ZInputStream(GetInputStream(), true);
                case CompressionAlgorithmTag.ZLib:
					return new ZInputStream(GetInputStream());
				case CompressionAlgorithmTag.BZip2:
					return new CBZip2InputStream(GetInputStream());
                default:
                    throw new PgpException("can't recognise compression algorithm: " + Algorithm);
            }
        }
    }
}
