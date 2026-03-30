using System.Collections.ObjectModel;
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Configuration;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.Models;

namespace VaultClient.Desktop.ViewModels;

public sealed partial class SecretsViewModel : ObservableObject
{
    private readonly VaultApiClient  _api;
    private readonly AutoTypeService _autoType;
    private readonly CredentialStore _credentials;
    private readonly IConfiguration  _config;

    public ObservableCollection<SecretItem> Secrets { get; } = [];

    [ObservableProperty] private bool   _isBusy;
    [ObservableProperty] private string _statusMessage  = string.Empty;
    [ObservableProperty] private bool   _isCountingDown;
    [ObservableProperty] private int    _countdownSeconds;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private bool   _isAdmin;

    public event EventHandler? LoggedOut;
    public event EventHandler? OpenSettings;
    public event EventHandler? OpenAdmin;

    // Leitura lazy — pickup imediato de mudancas feitas no SetupViewModel.Save()
    private string ClientId     => _credentials.Get(AppConfig.ClientIdKey)     ?? _config["Vault:ClientId"]     ?? "local-dev-client";
    private string ClientSecret => _credentials.Get(AppConfig.ClientSecretKey) ?? _config["Vault:ClientSecret"] ?? string.Empty;
    private Guid   VaultId      => Guid.Parse(_credentials.Get(AppConfig.VaultIdKey) ?? _config["Vault:VaultId"] ?? Guid.Empty.ToString());

    public SecretsViewModel(
        VaultApiClient api,
        AutoTypeService autoType,
        CredentialStore credentials,
        IConfiguration config)
    {
        _api         = api;
        _autoType    = autoType;
        _credentials = credentials;
        _config      = config;
    }

    [RelayCommand]
    private async Task LoadAsync()
    {
        IsBusy = true;
        StatusMessage = string.Empty;

        try
        {
            var items = await _api.ListSecretsAsync(VaultId);
            Secrets.Clear();
            foreach (var item in items)
                Secrets.Add(item);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erro ao carregar segredos: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Inicia o fluxo de Auto-Type para o segredo selecionado.
    /// O usuario tem CountdownSeconds para focar o campo de destino.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanAutoType))]
    private async Task AutoTypeAsync(SecretItem secret)
    {
        IsCountingDown = true;
        StatusMessage  = string.Empty;
        byte[]? valueBytes = null;

        try
        {
            var clientSecret = ClientSecret;
            if (string.IsNullOrWhiteSpace(clientSecret))
                throw new InvalidOperationException("Client Secret nao configurado. Acesse Configuracoes.");

            var fetchTask = _api.RequestSecretValueAsync(
                VaultId,
                secret.Name,
                ClientId,
                clientSecret,
                subject: GetCurrentSubject(),
                reason:  "Auto-Type via VaultClient Desktop",
                ticket:  "-");

            for (var i = 3; i >= 1; i--)
            {
                CountdownSeconds = i;
                await Task.Delay(1000);
            }

            valueBytes = await fetchTask;
            _autoType.Type(valueBytes);
            valueBytes = null;

            StatusMessage = $"Digitado: {secret.Name}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Falha no Auto-Type: {ex.Message}";

            if (valueBytes is not null)
                CryptographicOperations.ZeroMemory(valueBytes);
        }
        finally
        {
            IsCountingDown   = false;
            CountdownSeconds = 0;

            _ = Task.Delay(4000).ContinueWith(_ =>
            {
                if (StatusMessage.StartsWith("Digitado:"))
                    StatusMessage = string.Empty;
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }
    }

    private bool CanAutoType(SecretItem? secret)
        => secret is not null && !IsBusy && !IsCountingDown;

    [RelayCommand]
    private void Logout()
    {
        _api.Logout();
        LoggedOut?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void OpenSettingsPanel()
        => OpenSettings?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void OpenAdminPanel()
        => OpenAdmin?.Invoke(this, EventArgs.Empty);

    private static string GetCurrentSubject()
        => $"{Environment.UserDomainName}\\{Environment.UserName}";
}
