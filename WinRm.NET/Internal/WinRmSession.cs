namespace WinRm.NET.Internal
{
    using Microsoft.Extensions.Logging;

    internal static partial class Log
    {
        private static readonly Action<ILogger, AuthType, string, string, string, Exception?> RunningCommandMessage =
            LoggerMessage.Define<AuthType, string, string, string>(
                LogLevel.Debug,
                new EventId(1, nameof(RunningCommand)),
                "Running: '{AuthType}' '{Command}' on '{Host}' as '{User}'");

        public static void RunningCommand(ILogger? logger, AuthType authType, string command, string host, string? user)
        {
            if (logger == null)
            {
                return;
            }

            RunningCommandMessage(logger, authType, command, host, user ?? string.Empty, null);
        }
    }

    internal sealed class WinRmSession(ILogger? logger, string host, AuthType authType, string? user, string? password)
        : IWinRmSession
    {
        public IWinRmResult Run(string command)
        {
            Log.RunningCommand(logger, authType, command, host, user);

            return new WinRmResult();
        }
    }
}