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

        LoginButton.Click += OnLoginClick;
        PasswordBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Return) OnLoginClick(this, new RoutedEventArgs());
        };
        UsernameBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Return && DataContext is LoginViewModel { IsAdLogin: true })
                OnLoginClick(this, new RoutedEventArgs());
        };
    }

    private void OnLoginClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is LoginViewModel vm)
        {
            // AD login: passa null (sem senha), Local: passa o PasswordBox.Password
            var password = vm.IsAdLogin ? null : PasswordBox.Password;
            vm.LoginCommand.Execute(password);
        }
    }

    private void LocalRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (DataContext is LoginViewModel vm)
            vm.IsAdLogin = false;
    }
}
