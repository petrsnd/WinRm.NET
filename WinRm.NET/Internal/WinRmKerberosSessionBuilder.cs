namespace WinRm.NET.Internal
{
    using WinRm.NET;

    internal sealed class WinRmKerberosSessionBuilder(WinRmSessionBuilder parent)
        : IWinRmKerberosSessionBuilder
    {
        private string? user;

        public IWinRmSession Build(string host)
        {
            return new WinRmSession(parent.Logger,
                host,
                AuthType.Kerberos,
                this.user,
                null);
        }

        public IWinRmKerberosSessionBuilder WithUser(string user)
        {
            this.user = user;
            return this;
        }
    }
}