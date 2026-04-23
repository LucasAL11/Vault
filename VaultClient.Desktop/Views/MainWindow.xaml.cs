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
    private const int DWMWCP_DONOTROUND              = 1;

    private const int WM_NCCALCSIZE = 0x0083;
    private const int WM_NCHITTEST  = 0x0084;

    // Resize hit-test regions (returned from WM_NCHITTEST)
    private const int HTCLIENT      = 1;
    private const int HTLEFT        = 10;
    private const int HTRIGHT       = 11;
    private const int HTTOP         = 12;
    private const int HTTOPLEFT     = 13;
    private const int HTTOPRIGHT    = 14;
    private const int HTBOTTOM      = 15;
    private const int HTBOTTOMLEFT  = 16;
    private const int HTBOTTOMRIGHT = 17;

    private const int ResizeBorder = 6; // px

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int left, top, right, bottom; }

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);

        var hwnd = new WindowInteropHelper(this).Handle;

        // Square corners on Windows 11
        var corner = DWMWCP_DONOTROUND;
        DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref corner, sizeof(int));

        // Hook WndProc to eliminate the NC area (white bar) and handle resize
        HwndSource.FromHwnd(hwnd)?.AddHook(WndProc);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        switch (msg)
        {
            // Returning 0 tells Windows the entire window rect is client area
            // → eliminates the 1px white NC border Win11 adds
            case WM_NCCALCSIZE when wParam != IntPtr.Zero:
                handled = true;
                return IntPtr.Zero;

            // Restore resize hit-testing since we removed the NC area
            case WM_NCHITTEST:
                var result = HitTest(hwnd, lParam);
                if (result != HTCLIENT)
                {
                    handled = true;
                    return new IntPtr(result);
                }
                break;
        }
        return IntPtr.Zero;
    }

    private int HitTest(IntPtr hwnd, IntPtr lParam)
    {
        if (WindowState == WindowState.Maximized)
            return HTCLIENT;

        GetWindowRect(hwnd, out var rc);

        var x = (short)(lParam.ToInt32() & 0xFFFF);
        var y = (short)(lParam.ToInt32() >> 16);

        var onLeft   = x < rc.left   + ResizeBorder;
        var onRight  = x > rc.right  - ResizeBorder;
        var onTop    = y < rc.top    + ResizeBorder;
        var onBottom = y > rc.bottom - ResizeBorder;

        if (onTop    && onLeft)  return HTTOPLEFT;
        if (onTop    && onRight) return HTTOPRIGHT;
        if (onBottom && onLeft)  return HTBOTTOMLEFT;
        if (onBottom && onRight) return HTBOTTOMRIGHT;
        if (onTop)               return HTTOP;
        if (onBottom)            return HTBOTTOM;
        if (onLeft)              return HTLEFT;
        if (onRight)             return HTRIGHT;

        return HTCLIENT;
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
        LoginPanel.Visibility         = Visibility.Collapsed;
        SecretsViewControl.Visibility = Visibility.Collapsed;
        AdminViewControl.Visibility   = Visibility.Collapsed;
        BtnMinimize.Visibility        = Visibility.Collapsed;
        BtnMaximize.Visibility        = Visibility.Collapsed;
    }

    private void ShowLogin()
    {
        LoginPanel.Visibility         = Visibility.Visible;
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
        LoginPanel.Visibility         = Visibility.Collapsed;
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
        LoginPanel.Visibility         = Visibility.Collapsed;
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
