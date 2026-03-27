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

        // HttpClient com base URL do appsettings
        services.AddHttpClient<VaultApiClient>(client =>
        {
            client.BaseAddress = new Uri(config["Vault:BaseUrl"]
                ?? throw new InvalidOperationException("Vault:BaseUrl não configurado."));
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            // Em desenvolvimento, aceita certificado auto-assinado
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        });

        services.AddTransient<LoginViewModel>();
        services.AddTransient<SecretsViewModel>();
        services.AddTransient<MainWindow>();

        _services = services.BuildServiceProvider();

        // Restaura sessão existente se houver JWT salvo
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
