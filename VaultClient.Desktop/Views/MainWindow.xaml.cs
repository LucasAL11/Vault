using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class MainWindow : Window
{
    // ── Window chrome handlers ────────────────────────────────────────────

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
            ToggleMaximize();
        else
            DragMove();
    }

    private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState.Minimized;

    private void BtnMaximize_Click(object sender, RoutedEventArgs e)
        => ToggleMaximize();

    private void BtnClose_Click(object sender, RoutedEventArgs e)
        => Close();

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;
    }


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

        // Decide initial screen
        if (!AppConfig.IsConfigured(credentials))
            ShowSetup();
        else if (api.HasSession)
            ShowSecrets();
        else
            ShowLogin();
    }

    // -- Navigation -------------------------------------------------------

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

        // Show admin button for both Global Admins and Vault Admins
        var isGlobalAdmin = JwtHelper.IsAdmin(_api.CurrentJwt);
        var isVaultAdmin  = JwtHelper.IsVaultAdmin(_api.CurrentJwt);
        _secretsVm.IsAdmin = isGlobalAdmin || isVaultAdmin;

        // Show vault name from the selected vault in admin, if available
        if (_adminVm.SelectedVault is not null)
            _secretsVm.VaultName = _adminVm.SelectedVault.Name;
    }

    private void ShowAdmin()
    {
        AdminViewControl.Visibility     = Visibility.Visible;
        SecretsViewControl.Visibility   = Visibility.Collapsed;
        SetupPanel.Visibility           = Visibility.Collapsed;
        LoginPanel.Visibility           = Visibility.Collapsed;

        _adminVm.IsGlobalAdmin = JwtHelper.IsAdmin(_api.CurrentJwt);
        _adminVm.LoadCommand.Execute(null);
    }

    // -- Handlers ---------------------------------------------------------

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
