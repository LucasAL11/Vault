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

    /// <summary>true = AD auth, false = local auth.</summary>
    [ObservableProperty]
    private bool _isAdLogin;

    public event EventHandler? LoginSucceeded;
    public event EventHandler? OpenSettings;

    partial void OnIsAdLoginChanged(bool value)
        => ErrorMessage = string.Empty;

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

            bool ok;

            if (IsAdLogin)
            {
                var domain = credentials.Get(AppConfig.DomainKey);
                if (string.IsNullOrWhiteSpace(domain))
                {
                    ErrorMessage = "Domínio AD não configurado. Acesse ⚙ Configurações.";
                    return;
                }

                ok = await api.LoginAdAsync(Username.Trim(), domain, password);
            }
            else
            {
                ok = await api.LoginLocalAsync(Username.Trim(), password);
            }

            if (ok)
                LoginSucceeded?.Invoke(this, EventArgs.Empty);
            else
                ErrorMessage = IsAdLogin
                    ? "Usuário ou senha inválidos no Active Directory."
                    : "Usuário ou senha inválidos.";
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
