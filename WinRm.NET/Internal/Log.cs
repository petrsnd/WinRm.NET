namespace WinRm.NET.Internal
{
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Provides logging helpers for WinRM session operations.
    /// </summary>
    internal static partial class Log
    {
        private static readonly Action<ILogger, string, string, string, AuthType, Exception?> RunningCommandMessage =
            LoggerMessage.Define<string, string, string, AuthType>(
                LogLevel.Information,
                new EventId(1, nameof(RunningCommand)),
                "[WINRM] Running: '{Command}' on '{Host}' as '{User}' using '{AuthType}' security");

        private static readonly Action<ILogger, string, Exception?> OpenedShellMessage =
            LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(2, nameof(OpenedShell)),
                "[WINRM] Opened shell {ShellId}");

        private static readonly Action<ILogger, string, string, Exception?> StartedCommandMessage =
            LoggerMessage.Define<string, string>(
                LogLevel.Information,
                new EventId(3, nameof(OpenedShell)),
                "[WINRM] Started command {ShellId}-{CommandId}");

        private static readonly Action<ILogger, string, string, int, Exception?> GotCommandResultMessage =
            LoggerMessage.Define<string, string, int>(
                LogLevel.Information,
                new EventId(4, nameof(OpenedShell)),
                "[WINRM] Got command result {ShellId}-{CommandId}: {StatusCode}");

        private static readonly Action<ILogger, string, string, Exception?> TerminatedCommandMessage =
            LoggerMessage.Define<string, string>(
                LogLevel.Information,
                new EventId(5, nameof(OpenedShell)),
                "[WINRM] Terminated command {ShellId}-{CommandId}");

        private static readonly Action<ILogger, string, Exception?> ClosedShellMessage =
            LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(6, nameof(OpenedShell)),
                "[WINRM] Closed shell {ShellId}");

        private static readonly Action<ILogger, string, Exception?> DbgMessage =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(7, nameof(DbgMessage)), "[WINRM] {Message}");

        private static readonly Action<ILogger, string, Exception?> ErrMessage =
            LoggerMessage.Define<string>(LogLevel.Error, new EventId(7, nameof(ErrMessage)), "[WINRM] {Message}");

        public static void Dbg(this ILogger? logger, string message)
        {
            if (logger == null)
            {
                return;
            }

            DbgMessage(logger, message, null);
        }

        public static void Err(ILogger? logger, string message, Exception ex)
        {
            if (logger == null)
            {
                return;
            }

            ErrMessage(logger, message, ex);
        }

        public static void RunningCommand(ILogger? logger, AuthType authType, string command, string host, string? user)
        {
            if (logger == null)
            {
                return;
            }

            RunningCommandMessage(logger, command, host, user ?? string.Empty, authType, null);
        }

        public static void OpenedShell(ILogger? logger, string shellId)
        {
            if (logger == null)
            {
                return;
            }

            OpenedShellMessage(logger, shellId, null);
        }

        public static void StartedCommand(ILogger? logger, string shellId, string commandId)
        {
            if (logger == null)
            {
                return;
            }

            StartedCommandMessage(logger, shellId, commandId, null);
        }

        public static void TerminatedCommand(ILogger? logger, string shellId, string commandId)
        {
            if (logger == null)
            {
                return;
            }

            TerminatedCommandMessage(logger, shellId, commandId, null);
        }

        public static void ClosedShell(ILogger? logger, string shellId)
        {
            if (logger == null)
            {
                return;
            }

            ClosedShellMessage(logger, shellId, null);
        }

        public static void GotCommandResult(ILogger? logger, string shellId, string commandId, int statusCode)
        {
            if (logger == null)
            {
                return;
            }

            GotCommandResultMessage(logger, shellId, commandId, statusCode, null);
        }
    }
}