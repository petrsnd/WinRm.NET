namespace WinRm.NET.Internal
{
    using System.ComponentModel.Design;
    using Microsoft.Extensions.Logging;

    internal static partial class Log
    {
        private static readonly Action<ILogger, string, string, string, AuthType, Exception?> RunningCommandMessage =
            LoggerMessage.Define<string, string, string, AuthType>(
                LogLevel.Debug,
                new EventId(1, nameof(RunningCommand)),
                "Running: '{Command}' on '{Host}' as '{User}' using '{AuthType}' security");

        private static readonly Action<ILogger, string, Exception?> OpenedShellMessage =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(2, nameof(OpenedShell)),
                "Opened shell {ShellId}");

        private static readonly Action<ILogger, string, string, Exception?> StartedCommandMessage =
            LoggerMessage.Define<string, string>(
                LogLevel.Debug,
                new EventId(3, nameof(OpenedShell)),
                "Started command {ShellId}-{CommandId}");

        private static readonly Action<ILogger, string, string, int, Exception?> GotCommandResultMessage =
            LoggerMessage.Define<string, string, int>(
                LogLevel.Debug,
                new EventId(4, nameof(OpenedShell)),
                "Got command result {ShellId}-{CommandId}: {StatusCode}");

        private static readonly Action<ILogger, string, string, Exception?> TerminatedCommandMessage =
            LoggerMessage.Define<string, string>(
                LogLevel.Debug,
                new EventId(5, nameof(OpenedShell)),
                "Terminated command {ShellId}-{CommandId}");

        private static readonly Action<ILogger, string, Exception?> ClosedShellMessage =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(6, nameof(OpenedShell)),
                "Closed shell {ShellId}");

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

    internal sealed class WinRmSession
            : IWinRmSession
    {
        private bool disposedValue;

        public WinRmSession(IHttpClientFactory clientFactory,
        ILogger? logger,
        string host,
        AuthType authType,
        string user,
        string? password)
        {
            HttpClientFactory = clientFactory;
            Logger = logger;
            Host = host;
            AuthType = authType;
            User = user;
            Password = password;
        }

        internal IHttpClientFactory HttpClientFactory { get; private set; }

        internal ILogger? Logger { get; private set; }

        internal string Host { get; private set; }

        internal AuthType AuthType { get; private set; }

        internal string User { get; private set; }

        internal string? Password { get; private set; }

        public async Task<IWinRmResult> Run(string command, IEnumerable<string>? arguments = null)
        {
            Log.RunningCommand(Logger, AuthType, command, Host, User);
            try
            {
                var protocol = new WinRmProtocol(this);

                // Step 1: Open a shell on the remote host
                var shellId = await protocol.OpenShell();
                Log.OpenedShell(Logger, shellId);

                try
                {
                    // Step 2: Execute the command in the remote shell
                    var commandId = await protocol.ExecuteCommand(shellId, command, arguments);
                    Log.StartedCommand(Logger, shellId, commandId);

                    try
                    {
                        // Step 3: Get the result of the command execution
                        var result = await protocol.GetCommandResult(shellId, commandId);
                        Log.GotCommandResult(Logger, shellId, commandId, result.StatusCode);

                        return new WinRmResult
                        {
                            IsSuccess = true,
                            Output = result.StdOutput,
                            Error = result.StdError,
                        };
                    }
                    finally
                    {
                        // Step 4: Cleanup the command (signal to exit if it timed out or hung)
                        await protocol.TerminateOperation(shellId, commandId);
                        Log.TerminatedCommand(Logger, shellId, commandId);
                    }
                }
                finally
                {
                    // Step 5: Close the shell
                    await protocol.CloseShell(shellId);
                    Log.ClosedShell(Logger, shellId);
                }
            }
            catch (Exception ex)
            {
                return new WinRmResult
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message,
                };
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // If this is our default factory, we need to clean it up
                    if (HttpClientFactory is DefaultHttpClientFactory factory)
                    {
                        factory.Dispose();
                    }
                }

                disposedValue = true;
            }
        }
    }
}