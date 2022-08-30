namespace Org.BouncyCastle.Extended.Crypto
{
    public interface IMacDerivationFunction:IDerivationFunction
    {
        IMac GetMac();
    }
}