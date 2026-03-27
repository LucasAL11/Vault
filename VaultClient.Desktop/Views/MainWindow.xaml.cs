using System.Windows;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class MainWindow : Window
{
    private readonly LoginViewModel   _loginVm;
    private readonly SecretsViewModel _secretsVm;
    private readonly SetupViewModel   _setupVm;
    private readonly AdminViewModel   _adminVm;
    private readonly VaultApiClient   _api;

    public MainWindow(
        LoginViewModel loginVm,
        SecretsViewModel secretsVm,
        SetupViewModel setupVm,
        AdminViewModel adminVm,
        CredentialStore credentials,
        VaultApiClient api)
    {
        InitializeComponent();

        _loginVm   = loginVm;
        _secretsVm = secretsVm;
        _setupVm   = setupVm;
        _adminVm   = adminVm;
        _api       = api;

        LoginViewControl.DataContext   = _loginVm;
        SecretsViewControl.DataContext = _secretsVm;
        SetupViewControl.DataContext   = _setupVm;
        AdminViewControl.DataContext   = _adminVm;

        _loginVm.LoginSucceeded     += OnLoginSucceeded;
        _loginVm.OpenSettings       += OnOpenSettings;
        _secretsVm.LoggedOut        += OnLoggedOut;
        _secretsVm.OpenSettings     += OnOpenSettings;
        _secretsVm.OpenAdmin        += OnOpenAdmin;
        _setupVm.SetupCompleted     += OnSetupCompleted;
        _adminVm.GoBack             += OnAdminGoBack;

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
        SetupPanel.Visibility           = Visibility.Visible;
        LoginPanel.Visibility           = Visibility.Collapsed;
        SecretsViewControl.Visibility   = Visibility.Collapsed;
        AdminViewControl.Visibility     = Visibility.Collapsed;
    }

    private void ShowLogin()
    {
        LoginPanel.Visibility           = Visibility.Visible;
        SetupPanel.Visibility           = Visibility.Collapsed;
        SecretsViewControl.Visibility   = Visibility.Collapsed;
        AdminViewControl.Visibility     = Visibility.Collapsed;
    }

    private void ShowSecrets()
    {
        SecretsViewControl.Visibility   = Visibility.Visible;
        SetupPanel.Visibility           = Visibility.Collapsed;
        LoginPanel.Visibility           = Visibility.Collapsed;
        AdminViewControl.Visibility     = Visibility.Collapsed;

        // Mostra/esconde botão admin com base nas claims do JWT
        _secretsVm.IsAdmin = JwtHelper.IsAdmin(_api.CurrentJwt);
    }

    private void ShowAdmin()
    {
        AdminViewControl.Visibility     = Visibility.Visible;
        SecretsViewControl.Visibility   = Visibility.Collapsed;
        SetupPanel.Visibility           = Visibility.Collapsed;
        LoginPanel.Visibility           = Visibility.Collapsed;

        _adminVm.LoadCommand.Execute(null);
    }

    // ── Handlers ─────────────────────────────────────────────────────────────

    private void OnLoginSucceeded(object? sender, EventArgs e)
        => ShowSecrets();

    private void OnLoggedOut(object? sender, EventArgs e)
        => ShowLogin();

    private void OnOpenSettings(object? sender, EventArgs e)
        => ShowSetup();

    private void OnOpenAdmin(object? sender, EventArgs e)
        => ShowAdmin();

    private void OnAdminGoBack(object? sender, EventArgs e)
        => ShowSecrets();

    private void OnSetupCompleted(object? sender, EventArgs e)
    {
        _api.Logout();
        ShowLogin();
    }
}
