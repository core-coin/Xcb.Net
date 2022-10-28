using Newtonsoft.Json;
using System.Collections.Generic;

namespace Xcb.Net.ABI.EIP712
{
    [JsonObject(MemberSerialization.OptIn)]
    public class TypedData<TDomain> : TypedDataRaw
    {
        [JsonProperty(PropertyName = "domain")]
        public TDomain Domain { get; set; }

        public void InitDomainRawValues()
        {
            DomainRawValues = MemberValueFactory.CreateFromMessage(Domain);
        }

        public void SetMessage<T>(T message)
        {
            Message = MemberValueFactory.CreateFromMessage(message);
        }

        public void EnsureDomainRawValuesAreInitialised()
        {
            if (DomainRawValues == null)
            {
                InitDomainRawValues();
            }
        }
    }
}