﻿using System;

namespace Org.BouncyCastle.Extended.Crypto
{
    /// <summary>
    /// Interface describing a provider of cipher builders for creating decrypting ciphers.
    /// </summary>
    public interface IDecryptorBuilderProvider
	{
        /// <summary>
        /// Return a cipher builder for creating decrypting ciphers.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm details/parameters to use to create the final cipher.</param>
        /// <returns>A new cipher builder.</returns>
        ICipherBuilder CreateDecryptorBuilder(object algorithmDetails);
    }
}
