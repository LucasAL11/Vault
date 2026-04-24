using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class MainWindow : Window
{
    // ── Win32 / DWM ──────────────────────────────────────────────────────

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_BORDER_COLOR             = 34;
    private const int DWMWCP_DONOTROUND              = 1;
    private const int DWMWA_COLOR_NONE               = unchecked((int)0xFFFFFFFE);

    // WM_ERASEBKGND: suppress default white erase → eliminates flash on minimize/restore
    private const int WM_ERASEBKGND = 0x0014;

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);

        var hwnd = new WindowInteropHelper(this).Handle;

        // Square corners on Windows 11
        var corner = DWMWCP_DONOTROUND;
        DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref corner, sizeof(int));

        // Remove the DWM system-accent border (white frame on alt+tab / snap previews)
        var noBorder = DWMWA_COLOR_NONE;
        DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ref noBorder, sizeof(int));

        // Hook WndProc only to suppress background erase flash
        HwndSource.FromHwnd(hwnd)?.AddHook(WndProc);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        // Suppress Win32 white background erase — prevents flash on minimize/restore
        if (msg == WM_ERASEBKGND)
        {
            handled = true;
            return new IntPtr(1);
        }
        return IntPtr.Zero;
    }

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

    // ── App fields ───────────────────────────────────────────────────────

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

        _loginVm.LoginSucceeded += OnLoginSucceeded;
        _loginVm.OpenSettings   += OnOpenSettings;
        _secretsVm.LoggedOut    += OnLoggedOut;
        _secretsVm.OpenSettings += OnOpenSettings;
        _secretsVm.OpenAdmin    += OnOpenAdmin;
        _setupVm.SetupCompleted += OnSetupCompleted;
        _adminVm.GoBack         += OnAdminGoBack;

        if (!AppConfig.IsConfigured(credentials))
            ShowSetup();
        else if (api.HasSession)
            ShowSecrets();
        else
            ShowLogin();
    }

    // ── Navigation ───────────────────────────────────────────────────────

    private void ShowSetup()
    {
        SetupPanel.Visibility         = Visibility.Visible;
        LoginViewControl.Visibility         = Visibility.Collapsed;
        SecretsViewControl.Visibility = Visibility.Collapsed;
        AdminViewControl.Visibility   = Visibility.Collapsed;
        BtnMinimize.Visibility        = Visibility.Collapsed;
        BtnMaximize.Visibility        = Visibility.Collapsed;
    }

    private void ShowLogin()
    {
        LoginViewControl.Visibility         = Visibility.Visible;
        SetupPanel.Visibility         = Visibility.Collapsed;
        SecretsViewControl.Visibility = Visibility.Collapsed;
        AdminViewControl.Visibility   = Visibility.Collapsed;
        // Login screen: only close button
        BtnMinimize.Visibility        = Visibility.Collapsed;
        BtnMaximize.Visibility        = Visibility.Collapsed;
    }

    private void ShowSecrets()
    {
        SecretsViewControl.Visibility = Visibility.Visible;
        SetupPanel.Visibility         = Visibility.Collapsed;
        LoginViewControl.Visibility         = Visibility.Collapsed;
        AdminViewControl.Visibility   = Visibility.Collapsed;
        BtnMinimize.Visibility        = Visibility.Visible;
        BtnMaximize.Visibility        = Visibility.Visible;

        var isGlobalAdmin = JwtHelper.IsAdmin(_api.CurrentJwt);
        var isVaultAdmin  = JwtHelper.IsVaultAdmin(_api.CurrentJwt);
        _secretsVm.IsAdmin = isGlobalAdmin || isVaultAdmin;

        if (_adminVm.SelectedVault is not null)
            _secretsVm.VaultName = _adminVm.SelectedVault.Name;
    }

    private void ShowAdmin()
    {
        AdminViewControl.Visibility   = Visibility.Visible;
        SecretsViewControl.Visibility = Visibility.Collapsed;
        SetupPanel.Visibility         = Visibility.Collapsed;
        LoginViewControl.Visibility         = Visibility.Collapsed;
        BtnMinimize.Visibility        = Visibility.Visible;
        BtnMaximize.Visibility        = Visibility.Visible;

        _adminVm.IsGlobalAdmin = JwtHelper.IsAdmin(_api.CurrentJwt);
        _adminVm.LoadCommand.Execute(null);
    }

    // ── Handlers ─────────────────────────────────────────────────────────

    private void OnLoginSucceeded(object? sender, EventArgs e) => ShowSecrets();
    private void OnLoggedOut(object? sender, EventArgs e)      => ShowLogin();
    private void OnOpenSettings(object? sender, EventArgs e)   => ShowSetup();
    private void OnOpenAdmin(object? sender, EventArgs e)      => ShowAdmin();
    private void OnAdminGoBack(object? sender, EventArgs e)    => ShowSecrets();

    private void OnSetupCompleted(object? sender, EventArgs e)
    {
        _api.Logout();
        ShowLogin();
    }
}
