namespace WinRm.NET.Internal
{
    using Microsoft.Extensions.Logging;
    using WinRm.NET;

    internal sealed class WinRmBuilder(AuthType authType, WinRmSessionBuilder parent)
        : IWinRmSessionBuilder
    {
        private string? user;
        private string? password;

        public IWinRmSession Build(string host)
        {
            if (user == null)
            {
                throw new InvalidOperationException("User must be specified");
            }

            return new WinRmSession(
                parent.HttpClientFactory ?? new DefaultHttpClientFactory(),
                parent.Logger,
                host,
                authType,
                this.user!,
                this.password);
        }

        public IWinRmSessionBuilder WithPassword(string password)
        {
            this.password = password;
            return this;
        }

        public IWinRmSessionBuilder WithUser(string user)
        {
            this.user = user;
            return this;
        }
    }
}