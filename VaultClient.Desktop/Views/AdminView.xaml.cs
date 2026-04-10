using System.Windows;
using System.Windows.Controls;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class AdminView : UserControl
{
    public AdminView()
    {
        InitializeComponent();

        CreateUserButton.Click += OnCreateUserClick;
    }

    private void OnCreateUserClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is AdminViewModel vm)
        {
            vm.CreateUserCommand.Execute(NewUserPasswordBox.Password);
            NewUserPasswordBox.Clear();
        }
    }

    private void VaultEnv_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string env && DataContext is AdminViewModel vm)
        {
            vm.NewVaultEnvironment = env;
        }
    }
}
