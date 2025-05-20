namespace WinRm.NET
{
    using System;
    using Microsoft.Extensions.DependencyInjection;

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection RegisterWinRm(this IServiceCollection services, Action<IWinRmConfig>? configure = null)
        {
            services.AddSingleton<IWinRm>(provider =>
            {
                var builder = new WinRmSessionBuilder();
                configure?.Invoke(builder);
                return builder;
            });

            return services;
        }
    }
}
