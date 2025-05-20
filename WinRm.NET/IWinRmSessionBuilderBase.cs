namespace WinRm.NET
{
    public interface IWinRmSessionBuilderBase
    {
        IWinRmSession Build(string host);
    }
}
