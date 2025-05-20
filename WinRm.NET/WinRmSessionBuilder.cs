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

    public sealed class WinRmSessionBuilder : IWinRm, IWinRmConfig
    {
        internal ILogger? Logger { get; private set; }

        internal IHttpClientFactory? HttpClientFactory { get; private set; }

        // Choose one of the following authentication types
        public IWinRmSessionBuilder WithKerberos() => new WinRmBuilder(AuthType.Kerberos, this);

        public IWinRmSessionBuilder WithNtlm() => new WinRmBuilder(AuthType.Ntlm, this);

        public IWinRmSessionBuilder WithBasic() => new WinRmBuilder(AuthType.Basic, this);

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
