using System.Windows;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class MainWindow : Window
{
    private readonly LoginViewModel _loginVm;
    private readonly SecretsViewModel _secretsVm;

    public MainWindow(LoginViewModel loginVm, SecretsViewModel secretsVm)
    {
        InitializeComponent();

        _loginVm = loginVm;
        _secretsVm = secretsVm;

        LoginViewControl.DataContext = _loginVm;
        SecretsViewControl.DataContext = _secretsVm;

        _loginVm.LoginSucceeded += OnLoginSucceeded;
        _secretsVm.LoggedOut += OnLoggedOut;
    }

    private void OnLoginSucceeded(object? sender, EventArgs e)
    {
        LoginPanel.Visibility = Visibility.Collapsed;
        SecretsViewControl.Visibility = Visibility.Visible;
    }

    private void OnLoggedOut(object? sender, EventArgs e)
    {
        SecretsViewControl.Visibility = Visibility.Collapsed;
        LoginPanel.Visibility = Visibility.Visible;
    }
}
