namespace WinRm.NET.Internal
{
    internal sealed class WinRmResult : IWinRmResult
    {
        public bool IsSuccess { get; set; }

        public string Output { get; set; } = string.Empty;

        public string Error { get; set; } = string.Empty;

        public string ErrorMessage { get; set; } = string.Empty;
    }
}