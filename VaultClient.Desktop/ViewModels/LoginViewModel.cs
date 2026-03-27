using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VaultClient.Desktop.Core;

namespace VaultClient.Desktop.ViewModels;

public sealed partial class LoginViewModel(VaultApiClient api) : ObservableObject
{
    [ObservableProperty]
    private string _username = string.Empty;

    [ObservableProperty]
    private string _errorMessage = string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    public event EventHandler? LoginSucceeded;

    [RelayCommand(CanExecute = nameof(CanLogin))]
    private async Task LoginAsync(string password)
    {
        ErrorMessage = string.Empty;
        IsBusy = true;

        try
        {
            var ok = await api.LoginAsync(Username.Trim(), password);
            if (ok)
                LoginSucceeded?.Invoke(this, EventArgs.Empty);
            else
                ErrorMessage = "Usuário ou senha inválidos.";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Falha na conexão: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanLogin(string? password)
        => !IsBusy && !string.IsNullOrWhiteSpace(Username) && !string.IsNullOrWhiteSpace(password);
}
