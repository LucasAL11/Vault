using System.Net.Http;
using System.Windows;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.ViewModels;
using VaultClient.Desktop.Views;

namespace VaultClient.Desktop;

public partial class App : Application
{
    private ServiceProvider? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false)
            .Build();

        var services = new ServiceCollection();

        services.AddSingleton<IConfiguration>(config);
        services.AddSingleton<CredentialStore>();
        services.AddSingleton<AutoTypeService>();

        // Singleton: todos os ViewModels compartilham a mesma instância.
        // Essencial para que Reconfigure() no SetupViewModel afete o LoginViewModel.
        services.AddSingleton<VaultApiClient>(sp =>
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            var http = new HttpClient(handler);
            return new VaultApiClient(
                http,
                sp.GetRequiredService<CredentialStore>(),
                sp.GetRequiredService<IConfiguration>());
        });

        services.AddTransient<LoginViewModel>();
        services.AddTransient<SetupViewModel>();
        services.AddTransient<SecretsViewModel>();
        services.AddTransient<AdminViewModel>();
        services.AddTransient<MainWindow>();

        _services = services.BuildServiceProvider();

        var api = _services.GetRequiredService<VaultApiClient>();
        api.RestoreSession();

        var window = _services.GetRequiredService<MainWindow>();
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _services?.Dispose();
        base.OnExit(e);
    }
}
