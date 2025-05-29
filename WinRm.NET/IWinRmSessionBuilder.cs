namespace WinRm.NET
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using WinRm.NET.Internal;

    public interface IWinRmSessionBuilder
    {
        IWinRmSession Build(string host);
    }

    public interface IWinRmSessionBuilder<T>
        : IWinRmSessionBuilder
    {
        T WithUser(string user);

        T WithPassword(string password);
    }

    public interface IWinRmBasicSessionBuilder
        : IWinRmSessionBuilder<IWinRmBasicSessionBuilder>
    {
    }

    public interface IWinRmNtlmSessionBuilder
        : IWinRmSessionBuilder<IWinRmNtlmSessionBuilder>
    {
    }

    public interface IWinRmKerberosSessionBuilder
        : IWinRmSessionBuilder<IWinRmKerberosSessionBuilder>
    {
        IWinRmKerberosSessionBuilder WithRealmName(string realm);

        IWinRmKerberosSessionBuilder WithKdc(string host, string address);
    }
}
