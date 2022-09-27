using System;
using Xcb.Net.ABI.Model;

namespace Xcb.Net.ABI.FunctionEncoding
{
    public class ParameterOutput
    {
        public Parameter Parameter { get; set; }
        public int DataIndexStart { get; set; }
        public object Result { get; set; }
        
    }
}