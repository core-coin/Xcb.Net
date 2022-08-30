using System;

namespace Org.BouncyCastle.Extended.Math.EC.Multiplier
{
    public interface IPreCompCallback
    {
        PreCompInfo Precompute(PreCompInfo existing);
    }
}
