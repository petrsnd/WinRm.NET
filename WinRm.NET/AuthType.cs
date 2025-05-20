namespace WinRm.NET
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Authentication types supported by WinRm.NET.
    /// </summary>
    public enum AuthType
    {
        Kerberos,
        Ntlm,
        Basic,
    }
}
