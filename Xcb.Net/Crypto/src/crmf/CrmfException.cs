﻿using System;

namespace Org.BouncyCastle.Extended.Crmf
{
    public class CrmfException
        : Exception
    {
        public CrmfException()
        {
        }

        public CrmfException(string message)
            : base(message)
        {
        }

        public CrmfException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
