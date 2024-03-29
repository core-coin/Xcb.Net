using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Extended.Asn1;
using Org.BouncyCastle.Extended.Asn1.Cms;
using Org.BouncyCastle.Extended.Asn1.Nist;
using Org.BouncyCastle.Extended.Asn1.Oiw;
using Org.BouncyCastle.Extended.Asn1.X509;
using Org.BouncyCastle.Extended.Asn1.X9;
using Org.BouncyCastle.Extended.Crypto;
using Org.BouncyCastle.Extended.Crypto.Generators;
using Org.BouncyCastle.Extended.Crypto.IO;
using Org.BouncyCastle.Extended.Crypto.Parameters;
using Org.BouncyCastle.Extended.Math;
using Org.BouncyCastle.Extended.Security;
using Org.BouncyCastle.Extended.Utilities;
using Org.BouncyCastle.Extended.Utilities.Date;
using Org.BouncyCastle.Extended.X509;

namespace Org.BouncyCastle.Extended.Cms
{
    /// <remarks>
    /// General class for generating a CMS enveloped-data message.
    ///
    /// A simple example of usage.
    ///
    /// <pre>
    ///      CmsEnvelopedDataGenerator  fact = new CmsEnvelopedDataGenerator();
    ///
    ///      fact.AddKeyTransRecipient(cert);
    ///
    ///      CmsEnvelopedData         data = fact.Generate(content, algorithm);
    /// </pre>
    /// </remarks>
    public class CmsEnvelopedDataGenerator
		: CmsEnvelopedGenerator
    {
		public CmsEnvelopedDataGenerator()
        {
        }

		/// <summary>Constructor allowing specific source of randomness</summary>
		/// <param name="rand">Instance of <c>SecureRandom</c> to use.</param>
		public CmsEnvelopedDataGenerator(
			SecureRandom rand)
			: base(rand)
		{
		}

		/// <summary>
		/// Generate an enveloped object that contains a CMS Enveloped Data
		/// object using the passed in key generator.
		/// </summary>
        private CmsEnvelopedData Generate(
            CmsProcessable		content,
            string				encryptionOid,
            CipherKeyGenerator	keyGen)
        {
            AlgorithmIdentifier encAlgId = null;
			KeyParameter encKey;
            Asn1OctetString encContent;

			try
			{
				byte[] encKeyBytes = keyGen.GenerateKey();
				encKey = ParameterUtilities.CreateKeyParameter(encryptionOid, encKeyBytes);

				Asn1Encodable asn1Params = GenerateAsn1Parameters(encryptionOid, encKeyBytes);

				ICipherParameters cipherParameters;
				encAlgId = GetAlgorithmIdentifier(
					encryptionOid, encKey, asn1Params, out cipherParameters);

				IBufferedCipher cipher = CipherUtilities.GetCipher(encryptionOid);
				cipher.Init(true, new ParametersWithRandom(cipherParameters, rand));

				MemoryStream bOut = new MemoryStream();
				CipherStream cOut = new CipherStream(bOut, null, cipher);

				content.Write(cOut);

                Platform.Dispose(cOut);

                encContent = new BerOctetString(bOut.ToArray());
			}
			catch (SecurityUtilityException e)
			{
				throw new CmsException("couldn't create cipher.", e);
			}
			catch (InvalidKeyException e)
			{
				throw new CmsException("key invalid in message.", e);
			}
			catch (IOException e)
			{
				throw new CmsException("exception decoding algorithm parameters.", e);
			}


			Asn1EncodableVector recipientInfos = new Asn1EncodableVector();

            foreach (RecipientInfoGenerator rig in recipientInfoGenerators)
            {
                try
                {
                    recipientInfos.Add(rig.Generate(encKey, rand));
                }
                catch (InvalidKeyException e)
                {
                    throw new CmsException("key inappropriate for algorithm.", e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CmsException("error making encrypted content.", e);
                }
            }

            EncryptedContentInfo eci = new EncryptedContentInfo(
                CmsObjectIdentifiers.Data,
                encAlgId,
                encContent);

			Asn1Set unprotectedAttrSet = null;
            if (unprotectedAttributeGenerator != null)
            {
                Asn1.Cms.AttributeTable attrTable = unprotectedAttributeGenerator.GetAttributes(Platform.CreateHashtable());

                unprotectedAttrSet = new BerSet(attrTable.ToAsn1EncodableVector());
            }

			ContentInfo contentInfo = new ContentInfo(
                CmsObjectIdentifiers.EnvelopedData,
                new EnvelopedData(null, new DerSet(recipientInfos), eci, unprotectedAttrSet));

            return new CmsEnvelopedData(contentInfo);
        }

		/// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(
            CmsProcessable	content,
            string			encryptionOid)
        {
            try
            {
				CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);
               
				keyGen.Init(new KeyGenerationParameters(rand, keyGen.DefaultStrength));

				return Generate(content, encryptionOid, keyGen);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("can't find key generation algorithm.", e);
            }
        }


        public CmsEnvelopedData Generate(CmsProcessable content, ICipherBuilderWithKey cipherBuilder)
        {
            //AlgorithmIdentifier encAlgId = null;
            KeyParameter encKey;
            Asn1OctetString encContent;

            try
            {
                encKey = (KeyParameter) cipherBuilder.Key;

                MemoryStream collector = new MemoryStream();
                Stream bOut = cipherBuilder.BuildCipher(collector).Stream;            
                content.Write(bOut);  
                Platform.Dispose(bOut);                            
                encContent = new BerOctetString(collector.ToArray());
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("couldn't create cipher.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key invalid in message.", e);
            }
            catch (IOException e)
            {
                throw new CmsException("exception decoding algorithm parameters.", e);
            }


            Asn1EncodableVector recipientInfos = new Asn1EncodableVector();

            foreach (RecipientInfoGenerator rig in recipientInfoGenerators)
            {
                try
                {
                    recipientInfos.Add(rig.Generate(encKey, rand));
                }
                catch (InvalidKeyException e)
                {
                    throw new CmsException("key inappropriate for algorithm.", e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CmsException("error making encrypted content.", e);
                }
            }

            EncryptedContentInfo eci = new EncryptedContentInfo(
                CmsObjectIdentifiers.Data,
                (AlgorithmIdentifier) cipherBuilder.AlgorithmDetails,
                encContent);

            Asn1Set unprotectedAttrSet = null;
            if (unprotectedAttributeGenerator != null)
            {
                Asn1.Cms.AttributeTable attrTable = unprotectedAttributeGenerator.GetAttributes(Platform.CreateHashtable());

                unprotectedAttrSet = new BerSet(attrTable.ToAsn1EncodableVector());
            }

            ContentInfo contentInfo = new ContentInfo(
                CmsObjectIdentifiers.EnvelopedData,
                new EnvelopedData(null, new DerSet(recipientInfos), eci, unprotectedAttrSet));

            return new CmsEnvelopedData(contentInfo);
        }

		/// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(
            CmsProcessable  content,
            string          encryptionOid,
            int             keySize)
        {
            try
            {
				CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

				keyGen.Init(new KeyGenerationParameters(rand, keySize));

				return Generate(content, encryptionOid, keyGen);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("can't find key generation algorithm.", e);
            }
        }
    }
}
