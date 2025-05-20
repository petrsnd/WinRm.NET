namespace WinRm.NET.Internal
{
    internal sealed class WinRmResult : IWinRmResult
    {
        public bool IsSuccess => true;

        public string Output => "This is the output";

        public string Error => "This is the error";

        public string ErrorMessage => "this is the error message";
    }
}