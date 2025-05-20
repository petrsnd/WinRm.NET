namespace WinRm.NET.Internal
{
    internal sealed class CommandResult
    {
        public string StdOutput { get; set; } = string.Empty;

        public string StdError { get; set; } = string.Empty;

        public int StatusCode { get; set; }
    }
}