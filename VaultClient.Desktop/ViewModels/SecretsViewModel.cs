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

    public ObservableCollection<SecretItem>       Secrets         { get; } = [];
    public ObservableCollection<VaultItem>        AvailableVaults { get; } = [];
    public ObservableCollection<SecretAuditEntry> AuditEntries    { get; } = [];

    [ObservableProperty] private bool       _isBusy;
    [ObservableProperty] private string     _statusMessage  = string.Empty;
    [ObservableProperty] private bool       _isCountingDown;
    [ObservableProperty] private int        _countdownSeconds;
    [ObservableProperty] private string     _searchText     = string.Empty;
    [ObservableProperty] private bool       _isAdmin;
    [ObservableProperty] private bool       _isGlobalAdmin;
    [ObservableProperty] private string     _vaultName      = string.Empty;
    [ObservableProperty] private VaultItem? _activeVault;

    // User display (sidebar strip)
    public string Username     => Environment.UserName;
    public string DisplayName  => Environment.UserName;
    public string UserInitials => string.IsNullOrEmpty(Environment.UserName)
        ? "?"
        : Environment.UserName[0].ToString().ToUpper();

    // Selected secret + reveal state
    [ObservableProperty] private SecretItem? _selectedSecret;
    [ObservableProperty] private string      _revealedValue   = string.Empty;
    [ObservableProperty] private bool        _isRevealed;
    [ObservableProperty] private bool        _isRevealing;
    [ObservableProperty] private bool        _isLoadingAudit;
    [ObservableProperty] private bool        _hasAuditEntries;

    public event EventHandler? LoggedOut;
    public event EventHandler? OpenSettings;
    public event EventHandler? OpenAdmin;

    // Leitura lazy — pickup imediato de mudancas feitas no SetupViewModel.Save()
    private string ClientId     => _credentials.Get(AppConfig.ClientIdKey)     ?? _config["Vault:ClientId"]     ?? "local-dev-client";
    private string ClientSecret => _credentials.Get(AppConfig.ClientSecretKey) ?? _config["Vault:ClientSecret"] ?? string.Empty;

    /// <summary>
    /// Vault em uso: o selecionado na sidebar tem prioridade;
    /// fallback para o último vault persistido nas credenciais (sessão anterior).
    /// </summary>
    private Guid VaultId => ActiveVault?.Id
        ?? (Guid.TryParse(_credentials.Get(AppConfig.VaultIdKey) ?? _config["Vault:VaultId"], out var saved)
            ? saved
            : Guid.Empty);

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
            // ── 1. Carrega lista de cofres acessíveis (somente na primeira vez) ──
            if (AvailableVaults.Count == 0)
            {
                try
                {
                    var myVaults = await _api.ListMyVaultsAsync();
                    AvailableVaults.Clear();
                    foreach (var v in myVaults)
                        AvailableVaults.Add(v);

                    // Seleciona automaticamente o vault configurado no Setup (ou o primeiro disponível)
                    var configuredId = Guid.Parse(
                        _credentials.Get(AppConfig.VaultIdKey) ?? _config["Vault:VaultId"] ?? Guid.Empty.ToString());

                    if (ActiveVault is null)
                    {
                        var picked = myVaults.FirstOrDefault(v => v.Id == configuredId)
                                     ?? myVaults.FirstOrDefault();
                        if (picked is not null)
                        {
                            AppConfig.SaveSelectedVault(_credentials, picked.Id, picked.Name);
                            ActiveVault = picked;
                        }
                    }
                }
                catch
                {
                    // Sem acesso a /vaults/mine (ex: local auth sem AD) — continua com o vault configurado
                }
            }

            // ── 2. Atualiza o nome do cofre ativo na sidebar ─────────────────────
            VaultName = ActiveVault?.Name
                        ?? _credentials.Get(AppConfig.VaultNameKey)
                        ?? string.Empty;

            // ── 3. Carrega os segredos do vault ativo ────────────────────────────
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
    /// Ao trocar de vault na sidebar: limpa os segredos e recarrega para o novo vault.
    /// Guard: se IsBusy=true significa que o próprio LoadAsync está fazendo o set inicial
    /// de ActiveVault — não queremos re-entrar.
    /// </summary>
    partial void OnActiveVaultChanged(VaultItem? value)
    {
        if (value is null || IsBusy) return;
        VaultName      = value.Name;
        SelectedSecret = null;
        Secrets.Clear();
        LoadCommand.Execute(null);
    }

    /// <summary>
    /// Troca o vault ativo — chamado pelo botão na sidebar.
    /// Persiste a seleção para a próxima sessão.
    /// </summary>
    [RelayCommand]
    private void SelectVault(VaultItem vault)
    {
        if (vault.Id == ActiveVault?.Id) return;
        AppConfig.SaveSelectedVault(_credentials, vault.Id, vault.Name);
        ActiveVault = vault;
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
        // Limpa estado de sessão para que o próximo login recarregue do zero
        AvailableVaults.Clear();
        ActiveVault    = null;
        Secrets.Clear();
        SelectedSecret = null;
        AuditEntries.Clear();
        HasAuditEntries = false;
        VaultName      = string.Empty;
        StatusMessage  = string.Empty;
        LoggedOut?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void OpenSettingsPanel()
        => OpenSettings?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void OpenAdminPanel()
        => OpenAdmin?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Ao mudar o segredo selecionado, esconde o valor revelado e carrega o audit (se admin).
    /// </summary>
    partial void OnSelectedSecretChanged(SecretItem? value)
    {
        HideValue();
        AuditEntries.Clear();
        HasAuditEntries = false;

        if (value is not null && IsGlobalAdmin)
            LoadAuditCommand.Execute(value);
    }

    /// <summary>
    /// Carrega as entradas de auditoria do segredo selecionado.
    /// </summary>
    [RelayCommand]
    private async Task LoadAuditAsync(SecretItem secret)
    {
        IsLoadingAudit = true;
        try
        {
            var entries = await _api.GetSecretAuditAsync(VaultId, secret.Name, take: 20);
            AuditEntries.Clear();
            foreach (var e in entries)
                AuditEntries.Add(e);
            HasAuditEntries = AuditEntries.Count > 0;
        }
        catch
        {
            // Sem permissão ou falha de rede — silencioso
        }
        finally
        {
            IsLoadingAudit = false;
        }
    }

    /// <summary>
    /// Busca e exibe o valor do segredo em plaintext por 15 segundos (apenas admin geral).
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanReveal))]
    private async Task RevealAsync(SecretItem secret)
    {
        IsRevealing = true;
        RevealedValue = string.Empty;
        IsRevealed = false;

        byte[]? valueBytes = null;
        try
        {
            var clientSecret = ClientSecret;
            if (string.IsNullOrWhiteSpace(clientSecret))
                throw new InvalidOperationException("Client Secret não configurado.");

            valueBytes = await _api.RequestSecretValueAsync(
                VaultId, secret.Name, ClientId, clientSecret,
                subject: GetCurrentSubject(),
                reason:  "Reveal via Admin Desktop",
                ticket:  "-");

            RevealedValue = System.Text.Encoding.UTF8.GetString(valueBytes);
            IsRevealed = true;

            // Auto-esconde após 15 segundos
            _ = Task.Delay(15_000).ContinueWith(_ =>
            {
                HideValue();
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }
        catch (Exception ex)
        {
            StatusMessage = $"Falha ao revelar: {ex.Message}";
        }
        finally
        {
            if (valueBytes is not null)
                CryptographicOperations.ZeroMemory(valueBytes);
            IsRevealing = false;
        }
    }

    private bool CanReveal(SecretItem? secret)
        => secret is not null && IsGlobalAdmin && !IsRevealing && !IsCountingDown;

    [RelayCommand]
    private void CopyRevealed()
    {
        if (!string.IsNullOrEmpty(RevealedValue))
            System.Windows.Clipboard.SetText(RevealedValue);
    }

    [RelayCommand]
    private void CopyName()
    {
        if (SelectedSecret is not null)
            System.Windows.Clipboard.SetText(SelectedSecret.Name);
    }

    [RelayCommand]
    private void HideRevealed() => HideValue();

    private void HideValue()
    {
        IsRevealed    = false;
        RevealedValue = string.Empty;
    }

    private static string GetCurrentSubject()
        => $"{Environment.UserDomainName}\\{Environment.UserName}";
}
