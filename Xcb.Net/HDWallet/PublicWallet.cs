namespace Xcb.Net.HDWallet
{
    public class PublicWallet : WalletBase
    {
        private readonly ExtendedPublicKey _master;

        public PublicWallet(ExtendedPublicKey master)
        {
            _master = master;
        }

        public override string[] GetAddress(int networkId, params int[] index)
        {
            throw new System.NotImplementedException();
        }

        public override byte[] GetPublicKey(params int[] index)
        {
            throw new System.NotImplementedException();
        }
    }
}