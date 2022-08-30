using System;

using Org.BouncyCastle.Extended.Security;

namespace Org.BouncyCastle.Extended.Crypto.Parameters
{
    public class DsaKeyGenerationParameters
		: KeyGenerationParameters
    {
        private readonly DsaParameters parameters;

        public DsaKeyGenerationParameters(
            SecureRandom	random,
            DsaParameters	parameters)
			: base(random, parameters.P.BitLength - 1)
        {
            this.parameters = parameters;
        }

		public DsaParameters Parameters
        {
            get { return parameters; }
        }
    }

}
