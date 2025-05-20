namespace WinRm.NET.Internal
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection.Metadata;
    using System.Text;
    using System.Threading.Tasks;

    // Will this be sufficient for Kerberos? We might need something more here, but I'm not sure
    internal sealed class Credentials(string user, string? password = null)
    {
        public string User => user;

        public string? Password => password;
    }
}
