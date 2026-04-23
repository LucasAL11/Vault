using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VaultClient.Desktop.Core;

namespace VaultClient.Desktop.ViewModels;

public sealed partial class LoginViewModel(VaultApiClient api, CredentialStore credentials)
    : ObservableObject
{
    [ObservableProperty]
    private string _username = string.Empty;

    [ObservableProperty]
    private string _errorMessage = string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    public event EventHandler? LoginSucceeded;
    public event EventHandler? OpenSettings;

    [RelayCommand(CanExecute = nameof(CanLogin))]
    private async Task LoginAsync(string? password)
    {
        ErrorMessage = string.Empty;
        IsBusy = true;

        try
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                ErrorMessage = "Informe a senha.";
                return;
            }

            var domain = credentials.Get(AppConfig.DomainKey);
            var useAd  = !string.IsNullOrWhiteSpace(domain);

            if (useAd)
                await api.LoginAdAsync(Username.Trim(), domain!, password);
            else
                await api.LoginLocalAsync(Username.Trim(), password);

            LoginSucceeded?.Invoke(this, EventArgs.Empty);
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

    [RelayCommand]
    private void GoToSettings()
        => OpenSettings?.Invoke(this, EventArgs.Empty);

    private bool CanLogin(string? password)
        => !IsBusy
           && !string.IsNullOrWhiteSpace(Username)
           && !string.IsNullOrWhiteSpace(password);
}
