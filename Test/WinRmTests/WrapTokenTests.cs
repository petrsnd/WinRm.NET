namespace WinRmTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public class WrapTokenTests
    {
        [Fact]
        public void WrapToken_RotateWorks()
        {
            var bytes = new byte[] { 1,2,3,4,5,6,7,8 };
            var expected = new byte[] { 5,6,7,8,1,2,3,4 };
            var rotated = WinRm.NET.Internal.Kerberos.GssWrap.Rotate(bytes, 4);
            Assert.Equal(expected, rotated.ToArray());
        }
    }
}
