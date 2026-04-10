using System.Windows.Controls;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class SetupView : UserControl
{
    public SetupView()
    {
        InitializeComponent();

        // Passa o secret para o ViewModel sempre que mudar — valor nunca exposto via binding
        ClientSecretBox.PasswordChanged += (_, _) =>
        {
            if (DataContext is SetupViewModel vm)
                vm.SetClientSecret(ClientSecretBox.Password);
        };

        TestButton.Click += (_, _) =>
        {
            if (DataContext is SetupViewModel vm)
                vm.TestConnectionCommand.Execute(null);
        };

        SaveButton.Click += (_, _) =>
        {
            if (DataContext is SetupViewModel vm)
                vm.SaveCommand.Execute(null);
        };

        // Bind SaveCommand.CanExecute ao IsEnabled do botao
        DataContextChanged += (_, _) =>
        {
            if (DataContext is SetupViewModel vm)
            {
                // Pre-fill PasswordBox se ja havia secret salvo (modo edicao)
                var stored = vm.StoredClientSecret;
                if (!string.IsNullOrEmpty(stored))
                {
                    ClientSecretBox.Password = stored;
                    vm.SetClientSecret(stored);
                }

                vm.SaveCommand.CanExecuteChanged += (_, _) =>
                    SaveButton.IsEnabled = vm.SaveCommand.CanExecute(null);

                SaveButton.IsEnabled = vm.SaveCommand.CanExecute(null);
            }
        };
    }
}
