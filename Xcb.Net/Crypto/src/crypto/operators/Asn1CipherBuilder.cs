﻿using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.Nist;
using Org.BouncyCastle.Extended.Asn1.Ntt;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Cms;
using Org.BouncyCastle.Extended.Crypto.IO;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Crypto.Utilities;
using Org.BouncyCastle.Extended.Security;
using Org.BouncyCastle.Extended.Utilities;

namespace Org.BouncyCastle.Extended.Crypto.Operators
{
    public class Asn1CipherBuilderWithKey : ICipherBuilderWithKey
    {
        private readonly KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;

        public Asn1CipherBuilderWithKey(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random)
        {
            if (random == null)
            {
                random = new SecureRandom();
            }

            CipherKeyGenerator keyGen = CipherKeyGeneratorFactory.CreateKeyGenerator(encryptionOID, random);

            encKey = new KeyParameter(keyGen.GenerateKey());
            algorithmIdentifier = AlgorithmIdentifierFactory.GenerateEncryptionAlgID(encryptionOID, encKey.GetKey().Length * 8, random);
        }

        public object AlgorithmDetails
        {
            get { return algorithmIdentifier; }
        }

        public int GetMaxOutputSize(int inputLen)
        {
            throw new NotImplementedException();
        }

        public ICipher BuildCipher(Stream stream)
        {
            object cipher = EnvelopedDataHelper.CreateContentCipher(true, encKey, algorithmIdentifier);

            //
            // BufferedBlockCipher
            // IStreamCipher
            //

            if (cipher is IStreamCipher)
            {
                cipher = new BufferedStreamCipher((IStreamCipher)cipher);
            }

            if (stream == null)
            {
                stream = new MemoryStream();
            }

            return new BufferedCipherWrapper((IBufferedCipher)cipher, stream);
        }

        public ICipherParameters Key
        {
            get { return encKey; }
        }
    }

    public class BufferedCipherWrapper : ICipher
    {
        private readonly IBufferedCipher bufferedCipher;
        private readonly CipherStream stream;

        public BufferedCipherWrapper(IBufferedCipher bufferedCipher, Stream source)
        {
            this.bufferedCipher = bufferedCipher;
            stream = new CipherStream(source, bufferedCipher, bufferedCipher);
        }

        public int GetMaxOutputSize(int inputLen)
        {
            return bufferedCipher.GetOutputSize(inputLen);
        }

        public int GetUpdateOutputSize(int inputLen)
        {
            return bufferedCipher.GetUpdateOutputSize(inputLen);
        }

        public Stream Stream
        {
            get { return stream; }
        }
    }
}
