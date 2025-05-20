namespace WinRm.NET
{
    public interface IWinRmKerberosSessionBuilder : IWinRmSessionBuilderBase
    {
        IWinRmKerberosSessionBuilder WithUser(string user);
    }
}