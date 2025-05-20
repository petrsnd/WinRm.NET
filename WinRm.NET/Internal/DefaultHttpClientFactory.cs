namespace WinRm.NET.Internal
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    // This is what we use if we aren't provided with an IHttpClientFactory
    internal sealed class DefaultHttpClientFactory : IHttpClientFactory, IDisposable
    {
        private readonly Lazy<HttpMessageHandler> _handlerLazy = new (() => new HttpClientHandler());

        public HttpClient CreateClient(string name) => new (_handlerLazy.Value, disposeHandler: false);

        public void Dispose()
        {
            if (_handlerLazy.IsValueCreated)
            {
                _handlerLazy.Value.Dispose();
            }
        }
    }
}
