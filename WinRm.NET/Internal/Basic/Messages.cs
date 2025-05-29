namespace WinRm.NET.Internal.Basic
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal static class Messages
    {
        public const string UnauthorizedError = @"
ERROR: Unauthorized. Either the username and password are incorrect, or the target host does
not accept Basic authentication. 

By default, WinRM does not accept Basic authentication or unencrypted payloads. You must 
configure the WinRM target to allow this non-secure configuration. Warning: Everything is
sent in plain text, including your credentials. This is only for development and testing
purposes in a trusted environment. Do not use this in production.

From an elevated PowerShell prompt, run the following commands (does not work in cmd.exe):

winrm set winrm/config/service '@{AllowUnencrypted=""true""}'
winrm set winrm/config/service/auth '@{Basic=""true""}'
";
    }
}
