using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class LoginView : UserControl
{
    public LoginView()
    {
        InitializeComponent();

        // Passa o PasswordBox.Password para o comando ao clicar/Enter
        // O valor nunca é exposto via binding — fica somente no PasswordBox
        LoginButton.Click += OnLoginClick;
        PasswordBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Return) OnLoginClick(this, new RoutedEventArgs());
        };
    }

    private void OnLoginClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is LoginViewModel vm)
            vm.LoginCommand.Execute(PasswordBox.Password);
    }
}
