namespace WinRm.NET
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using WinRm.NET.Internal;
    using WinRm.NET.Internal.Basic;
    using WinRm.NET.Internal.Kerberos;
    using WinRm.NET.Internal.Ntlm;

    public sealed class WinRmSessionBuilder : IWinRm, IWinRmConfig
    {
        internal ILogger? Logger { get; private set; }

        internal IHttpClientFactory? HttpClientFactory { get; private set; }

        // Choose one of the following authentication types
        public IWinRmKerberosSessionBuilder WithKerberos() => new WinRmKerberosBuilder(this);

        public IWinRmNtlmSessionBuilder WithNtlm() => new WinRmNtlmBuilder(this);

        public IWinRmBasicSessionBuilder WithBasic() => new WinRmBasicBuilder(this);

        // Integration points
        public IWinRm WithLogger(ILogger logger)
        {
            Logger = logger;
            return this;
        }

        public IWinRm WithHttpClientFactory(IHttpClientFactory httpClientFactory)
        {
            HttpClientFactory = httpClientFactory;
            return this;
        }
    }
}
