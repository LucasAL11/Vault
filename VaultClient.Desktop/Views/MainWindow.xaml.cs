using System.Windows;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class MainWindow : Window
{
    private readonly LoginViewModel   _loginVm;
    private readonly SecretsViewModel _secretsVm;
    private readonly SetupViewModel   _setupVm;
    private readonly VaultApiClient   _api;

    public MainWindow(
        LoginViewModel loginVm,
        SecretsViewModel secretsVm,
        SetupViewModel setupVm,
        CredentialStore credentials,
        VaultApiClient api)
    {
        InitializeComponent();

        _loginVm   = loginVm;
        _secretsVm = secretsVm;
        _setupVm   = setupVm;
        _api       = api;

        LoginViewControl.DataContext   = _loginVm;
        SecretsViewControl.DataContext = _secretsVm;
        SetupViewControl.DataContext   = _setupVm;

        _loginVm.LoginSucceeded     += OnLoginSucceeded;
        _secretsVm.LoggedOut        += OnLoggedOut;
        _secretsVm.OpenSettings     += OnOpenSettings;
        _setupVm.SetupCompleted     += OnSetupCompleted;

        // Decide a tela inicial
        if (!AppConfig.IsConfigured(credentials))
            ShowSetup();
        else if (api.HasSession)
            ShowSecrets();
        else
            ShowLogin();
    }

    // ── Navegação ─────────────────────────────────────────────────────────────

    private void ShowSetup()
    {
        SetupPanel.Visibility      = Visibility.Visible;
        LoginPanel.Visibility      = Visibility.Collapsed;
        SecretsViewControl.Visibility = Visibility.Collapsed;
    }

    private void ShowLogin()
    {
        LoginPanel.Visibility      = Visibility.Visible;
        SetupPanel.Visibility      = Visibility.Collapsed;
        SecretsViewControl.Visibility = Visibility.Collapsed;
    }

    private void ShowSecrets()
    {
        SecretsViewControl.Visibility = Visibility.Visible;
        SetupPanel.Visibility      = Visibility.Collapsed;
        LoginPanel.Visibility      = Visibility.Collapsed;
    }

    // ── Handlers ─────────────────────────────────────────────────────────────

    private void OnLoginSucceeded(object? sender, EventArgs e)
        => ShowSecrets();

    private void OnLoggedOut(object? sender, EventArgs e)
        => ShowLogin();

    private void OnOpenSettings(object? sender, EventArgs e)
        => ShowSetup();

    private void OnSetupCompleted(object? sender, EventArgs e)
    {
        // URL ou credenciais podem ter mudado — descarta sessão e pede novo login
        _api.Logout();
        ShowLogin();
    }
}
