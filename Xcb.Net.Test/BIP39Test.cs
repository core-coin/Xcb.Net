using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Xcb.Net.Test
{
    public class BIP39Test
    {
        [Fact]
        public void ValidMnemonic()
        {
            // Given
            var validMnemonic = "urge genuine pelican eagle blouse emotion refuse fringe flock salute space climb marriage empower feature inform ostrich endless fault barely chronic shy couple wonder";

            // When
            var mnemonic = new BIP39.Mnemoic(validMnemonic);

            // Then
            Assert.NotNull(mnemonic);
        }

        [Fact]
        public void InvalidMnemonic()
        {
            // Given
            var validMnemonic = "zoo genuine pelican eagle blouse emotion refuse fringe flock salute space climb marriage empower feature inform ostrich endless fault barely chronic shy couple wonder";


            // When
            Assert.Throws<ArgumentException>(() => new BIP39.Mnemoic(validMnemonic));

        }
    }
}