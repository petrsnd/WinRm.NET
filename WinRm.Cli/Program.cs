namespace WinRm.Cli
{
    using CommandLine;
    using Serilog;
    using Serilog.Extensions.Logging;
    using WinRm.Cli.Commands;
    using WinRm.NET;

    internal sealed class Program
    {
        public static async Task<int> Main(string[] args)
        {
            var parser = new Parser(cfg =>
            {
                cfg.CaseInsensitiveEnumValues = true;
                cfg.HelpWriter = Console.Out;
            });
            var result = parser.ParseArguments<RunCommandOptions>(args);
            if (result is Parsed<RunCommandOptions> parsed)
            {
                return await RunCommand(parsed.Value);
            }
            else if (result is NotParsed<RunCommandOptions> notParsed)
            {
                return await HandleParseError(result, notParsed.Errors);
            }

            throw new InvalidOperationException("You broke the command line parser.");
        }

        private static async Task<int> RunCommand(RunCommandOptions opts)
        {
            // If using DI, register this in the container and configure it
            // with logging and httpclientfactory
            var sessionBuilder = new WinRmSessionBuilder();
            if (opts.Verbose)
            {
                // Set up logging
                using var log = new LoggerConfiguration()
                .WriteTo.Console()
                .MinimumLevel.Debug()
                .CreateLogger();
                var logBridge = new SerilogLoggerFactory(log);
                sessionBuilder.WithLogger(logBridge.CreateLogger("WinRm.NET"));
            }

            // Create the session
            using IWinRmSession session = opts.Authentication switch
            {
                AuthType.Kerberos => sessionBuilder.WithKerberos()
                    .WithUser(opts.UserName)
                    .WithPassword(opts.Password!)
                    .Build(opts.HostName),
                AuthType.Ntlm => sessionBuilder.WithNtlm()
                    .WithUser(opts.UserName)
                    .WithPassword(opts.Password!)
                    .Build(opts.HostName),
                AuthType.Basic => sessionBuilder.WithBasic()
                    .WithUser(opts.UserName)
                    .WithPassword(opts.Password!)
                    .Build(opts.HostName),
                _ => throw new NotImplementedException($"Authentication mode '{opts.Authentication}' is not implemented.")
            };

            // Run the command
            var result = await session.Run(opts.Command, opts.Arguments);

            // Show results
            if (result.IsSuccess)
            {
                if (!string.IsNullOrEmpty(result.Output))
                {
                    Console.WriteLine(result.Output);
                }
                else
                {
                    Console.WriteLine($"Command '{opts.Command}' executed successfully and returned no output.");
                }

                if (!string.IsNullOrEmpty(result.Error))
                {
                    Console.WriteLine($"STDERR: {result.Error}");
                }
            }
            else
            {
                Console.WriteLine($"Error: {result.ErrorMessage}");
            }

            return 0;
        }

        private static Task<int> HandleParseError<T>(ParserResult<T> result, IEnumerable<Error> errs)
        {
            return Task.FromResult(1);
        }
    }
}
