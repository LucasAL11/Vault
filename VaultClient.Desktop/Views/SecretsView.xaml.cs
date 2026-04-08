using System.Windows.Controls;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class SecretsView : UserControl
{
    public SecretsView()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            if (DataContext is SecretsViewModel vm)
                vm.LoadCommand.Execute(null);
        };
    }
}
