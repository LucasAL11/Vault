using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VaultClient.Desktop.Core;

namespace VaultClient.Desktop.ViewModels;

public sealed partial class SetupViewModel : ObservableObject
{
    private readonly CredentialStore _credentials;
    private readonly VaultApiClient _api;
    private string _clientSecretValue = string.Empty;

    [ObservableProperty] private string _baseUrl    = string.Empty;
    [ObservableProperty] private string _vaultId    = string.Empty;
    [ObservableProperty] private string _clientId   = string.Empty;
    [ObservableProperty] private string _domain     = string.Empty;
    [ObservableProperty] private string _errorMessage   = string.Empty;
    [ObservableProperty] private string _successMessage = string.Empty;
    [ObservableProperty] private bool   _isBusy;
    [ObservableProperty] private bool   _connectionVerified;

    /// <summary>Exposto apenas para pre-fill do PasswordBox no code-behind.</summary>
    public string? StoredClientSecret => _credentials.Get(AppConfig.ClientSecretKey);

    public event EventHandler? SetupCompleted;

    public SetupViewModel(CredentialStore credentials, VaultApiClient api)
    {
        _credentials = credentials;
        _api = api;

        // Pre-fill campos se já configurado (modo edição).
        // ClientId default: "vault-desktop" (nome registrado no servidor para este cliente).
        _baseUrl  = credentials.Get(AppConfig.BaseUrlKey)  ?? string.Empty;
        _vaultId  = credentials.Get(AppConfig.VaultIdKey)  ?? string.Empty;
        _clientId = credentials.Get(AppConfig.ClientIdKey) ?? "vault-desktop";
        _domain   = credentials.Get(AppConfig.DomainKey)   ?? string.Empty;
    }

    /// <summary>Chamado pelo code-behind sempre que o PasswordBox mudar.</summary>
    public void SetClientSecret(string value)
    {
        _clientSecretValue = value;
        ConnectionVerified = false;
        SaveCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private async Task TestConnectionAsync()
    {
        ErrorMessage   = string.Empty;
        SuccessMessage = string.Empty;
        IsBusy = true;
        ConnectionVerified = false;

        try
        {
            _api.Reconfigure(BaseUrl);
            await _api.PingAsync();
            SuccessMessage     = "Servidor acessivel.";
            ConnectionVerified = true;
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Falha na conexao: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            SaveCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanSave))]
    private void Save()
    {
        if (!Guid.TryParse(VaultId, out _))
        {
            ErrorMessage = "Vault ID deve ser um GUID valido.";
            return;
        }

        AppConfig.Save(_credentials, BaseUrl, VaultId, ClientId, _clientSecretValue,
            string.IsNullOrWhiteSpace(Domain) ? null : Domain.Trim());
        SetupCompleted?.Invoke(this, EventArgs.Empty);
    }

    private bool CanSave()
        => ConnectionVerified
           && !string.IsNullOrWhiteSpace(BaseUrl)
           && Guid.TryParse(VaultId, out _)
           && !string.IsNullOrWhiteSpace(ClientId)
           && !string.IsNullOrWhiteSpace(_clientSecretValue);

    partial void OnBaseUrlChanged(string value)
    {
        ConnectionVerified = false;
        SaveCommand.NotifyCanExecuteChanged();
    }

    partial void OnVaultIdChanged(string value)
        => SaveCommand.NotifyCanExecuteChanged();

    partial void OnClientIdChanged(string value)
        => SaveCommand.NotifyCanExecuteChanged();
}
