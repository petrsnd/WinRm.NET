namespace WinRm.NET
{
    using Microsoft.Extensions.Logging;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using WinRm.NET.Internal;

    public sealed class WinRmSessionBuilder
    {
        internal ILogger? Logger { get; private set; }

        public IWinRmKerberosSessionBuilder WithKerberos() => new WinRmKerberosSessionBuilder(this);

        public IWinRmNtlmSessionBuilder WithNtlm() => new WinRmNtlmSessionBuilder(this);

        public WinRmSessionBuilder WithLogger(ILogger logger)
        {
            Logger = logger;
            return this;
        }
    }
}
