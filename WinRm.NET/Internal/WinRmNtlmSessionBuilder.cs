namespace WinRm.NET.Internal
{
    using Microsoft.Extensions.Logging;
    using WinRm.NET;

    internal sealed class WinRmNtlmSessionBuilder(WinRmSessionBuilder parent) : IWinRmNtlmSessionBuilder
    {
        private string? user;
        private string? password;

        public IWinRmSession Build(string host)
        {
            return new WinRmSession(
                parent.Logger,
                host,
                AuthType.Ntlm,
                this.user,
                this.password);
        }

        public IWinRmNtlmSessionBuilder WithPassword(string password)
        {
            this.password = password;
            return this;
        }

        public IWinRmNtlmSessionBuilder WithUser(string user)
        {
            this.user = user;
            return this;
        }
    }
}