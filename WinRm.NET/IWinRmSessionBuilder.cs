namespace WinRm.NET
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public interface IWinRmSessionBuilder
    {
        IWinRmSession Build(string host);

        IWinRmSessionBuilder WithUser(string user);

        IWinRmSessionBuilder WithPassword(string password);
    }
}
