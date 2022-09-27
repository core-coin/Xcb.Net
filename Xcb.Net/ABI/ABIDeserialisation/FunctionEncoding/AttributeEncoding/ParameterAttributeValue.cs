using System.Reflection;
using Xcb.Net.ABI.FunctionEncoding.Attributes;

namespace Xcb.Net.ABI.FunctionEncoding.AttributeEncoding
{
    public class ParameterAttributeValue
    {
        public ParameterAttribute ParameterAttribute { get; set; }
        public object Value { get; set; }
        public PropertyInfo PropertyInfo { get; set; }
    }
}