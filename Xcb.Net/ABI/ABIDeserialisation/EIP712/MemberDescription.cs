using Xcb.Net.ABI;
using Xcb.Net.ABI.FunctionEncoding.Attributes;
using Xcb.Net.ABI.Model;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Xcb.Net.ABI.EIP712
{
    public class MemberDescription
    {
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        [JsonProperty(PropertyName = "type")]
        public string Type { get; set; }
    }
}