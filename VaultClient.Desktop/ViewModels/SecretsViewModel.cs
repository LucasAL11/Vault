using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Configuration;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.Models;

namespace VaultClient.Desktop.ViewModels;

public sealed partial class SecretsViewModel : ObservableObject
{
    private readonly VaultApiClient _api;
    private readonly AutoTypeService _autoType;
    private readonly CredentialStore _credentials;
    private readonly string _clientId;
    private readonly Guid _vaultId;

    public ObservableCollection<SecretItem> Secrets { get; } = [];

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusMessage = string.Empty;
    [ObservableProperty] private bool _isCountingDown;
    [ObservableProperty] private int _countdownSeconds;
    [ObservableProperty] private string _searchText = string.Empty;

    public event EventHandler? LoggedOut;

    public SecretsViewModel(
        VaultApiClient api,
        AutoTypeService autoType,
        CredentialStore credentials,
        IConfiguration config)
    {
        _api = api;
        _autoType = autoType;
        _credentials = credentials;
        _clientId = config["Vault:ClientId"] ?? "local-dev-client";
        _vaultId = Guid.Parse(config["Vault:VaultId"] ?? Guid.Empty.ToString());
    }

    [RelayCommand]
    private async Task LoadAsync()
    {
        IsBusy = true;
        StatusMessage = string.Empty;

        try
        {
            var items = await _api.ListSecretsAsync(_vaultId);
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
    /// O usuário tem CountdownSeconds para focar no campo de destino.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanAutoType))]
    private async Task AutoTypeAsync(SecretItem secret)
    {
        IsCountingDown = true;
        StatusMessage = string.Empty;
        byte[]? valueBytes = null;

        try
        {
            // Buscar o valor enquanto o countdown corre em paralelo
            var clientSecret = _credentials.Get("client_secret")
                ?? throw new InvalidOperationException("Client secret não configurado.");

            var fetchTask = _api.RequestSecretValueAsync(
                _vaultId,
                secret.Name,
                _clientId,
                clientSecret,
                subject: GetCurrentSubject(),
                reason: "Auto-Type via VaultClient Desktop",
                ticket: "-");

            // Countdown de 3 segundos para o usuário focar o campo
            for (var i = 3; i >= 1; i--)
            {
                CountdownSeconds = i;
                await Task.Delay(1000);
            }

            valueBytes = await fetchTask;

            // Digita o valor na janela focada via SendInput
            _autoType.Type(valueBytes);
            valueBytes = null; // Type() já zerou o array

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
            IsCountingDown = false;
            CountdownSeconds = 0;

            // Limpa a mensagem de status após 4s
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

    private string GetCurrentSubject()
    {
        // Usa o nome de usuário do Windows como subject para o HMAC
        return $"{Environment.UserDomainName}\\{Environment.UserName}";
    }
}
