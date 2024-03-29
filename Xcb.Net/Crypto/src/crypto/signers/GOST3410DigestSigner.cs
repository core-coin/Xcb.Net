using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Crypto.Signers;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Signers
{
    public class Gost3410DigestSigner
        : ISigner
    {
        private readonly IDigest digest;
        private readonly IDsa dsaSigner;
        private readonly int size;
        private int halfSize;
        private bool forSigning;



        public Gost3410DigestSigner(
            IDsa signer,
            IDigest digest)
        {
            this.dsaSigner = signer;
            this.digest = digest;

            halfSize = digest.GetDigestSize();
            this.size = halfSize * 2;

        }

        public virtual string AlgorithmName
        {
            get { return digest.AlgorithmName + "with" + dsaSigner.AlgorithmName; }
        }

        public virtual void Init(
            bool forSigning,
            ICipherParameters parameters)
        {
            this.forSigning = forSigning;

            AsymmetricKeyParameter k;
            if (parameters is ParametersWithRandom)
            {
                k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).Parameters;
            }
            else
            {
                k = (AsymmetricKeyParameter)parameters;
            }

            if (forSigning && !k.IsPrivate)
            {
                throw new InvalidKeyException("Signing Requires Private Key.");
            }

            if (!forSigning && k.IsPrivate)
            {
                throw new InvalidKeyException("Verification Requires Public Key.");
            }


            Reset();

            dsaSigner.Init(forSigning, parameters);
        }

        /**
		 * update the internal digest with the byte b
		 */
        public virtual void Update(
            byte input)
        {
            digest.Update(input);
        }

        /**
		 * update the internal digest with the byte array in
		 */
        public virtual void BlockUpdate(
            byte[] input,
            int inOff,
            int length)
        {
            digest.BlockUpdate(input, inOff, length);
        }

        /**
		 * Generate a signature for the message we've been loaded with using
		 * the key we were initialised with.
		 */
        public virtual byte[] GenerateSignature()
        {
            if (!forSigning)
                throw new InvalidOperationException("GOST3410DigestSigner not initialised for signature generation.");

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            try
            {
                BigInteger[] sig = dsaSigner.GenerateSignature(hash);
                byte[] sigBytes = new byte[size];

                // TODO Add methods to allow writing BigInteger to existing byte array?
                byte[] r = sig[0].ToByteArrayUnsigned();
                byte[] s = sig[1].ToByteArrayUnsigned();
                s.CopyTo(sigBytes, halfSize - s.Length);
                r.CopyTo(sigBytes, size - r.Length);
                return sigBytes;
            }
            catch (Exception e)
            {
                throw new SignatureException(e.Message, e);
            }
        }

        /// <returns>true if the internal state represents the signature described in the passed in array.</returns>
        public virtual bool VerifySignature(
            byte[] signature)
        {
            if (forSigning)
                throw new InvalidOperationException("DSADigestSigner not initialised for verification");

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            BigInteger R, S;
            try
            {
                R = new BigInteger(1, signature, halfSize, halfSize);
                S = new BigInteger(1, signature, 0, halfSize);
            }
            catch (Exception e)
            {
                throw new SignatureException("error decoding signature bytes.", e);
            }

            return dsaSigner.VerifySignature(hash, R, S);
        }

        /// <summary>Reset the internal state</summary>
        public virtual void Reset()
        {
            digest.Reset();
        }
    }
}
