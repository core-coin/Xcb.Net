﻿using System;

namespace Org.BouncyCastle.Extended.Math.EC
{
    public interface ECLookupTable
    {
        int Size { get; }
        ECPoint Lookup(int index);
        ECPoint LookupVar(int index);
    }
}
