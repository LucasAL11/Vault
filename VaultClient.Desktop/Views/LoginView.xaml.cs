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
    }

    private void OnLoginClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is LoginViewModel vm)
            vm.LoginCommand.Execute(PasswordBox.Password);
    }

    private void LocalRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (DataContext is LoginViewModel vm)
            vm.IsAdLogin = false;
    }
}
