namespace WinRm.NET
{
    public interface IWinRmNtlmSessionBuilder : IWinRmSessionBuilderBase
    {
        IWinRmNtlmSessionBuilder WithUser(string user);

        IWinRmNtlmSessionBuilder WithPassword(string password);
    }
}