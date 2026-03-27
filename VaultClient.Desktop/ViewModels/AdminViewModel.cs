using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Configuration;
using VaultClient.Desktop.Core;
using VaultClient.Desktop.Models;

namespace VaultClient.Desktop.ViewModels;

public sealed partial class AdminViewModel : ObservableObject
{
    private readonly VaultApiClient  _api;
    private readonly CredentialStore _credentials;
    private readonly IConfiguration  _config;

    public ObservableCollection<SecretItem> Secrets { get; } = [];
    public ObservableCollection<AdMapItem>  AdMaps  { get; } = [];
    public ObservableCollection<UserItem>   Users   { get; } = [];

    [ObservableProperty] private bool   _isBusy;
    [ObservableProperty] private string _statusMessage = string.Empty;

    // ── Aba ativa ──────────────────────────────────────────────────────────
    [ObservableProperty] private int _selectedTab; // 0=Secrets, 1=AD Maps, 2=Users

    // ── Formulários ────────────────────────────────────────────────────────

    // Secret
    [ObservableProperty] private string _newSecretName  = string.Empty;
    [ObservableProperty] private string _newSecretValue = string.Empty;
    [ObservableProperty] private string _newSecretContentType = string.Empty;

    // AD Map
    [ObservableProperty] private string _newAdMapGroupId    = string.Empty;
    [ObservableProperty] private string _newAdMapPermission = "Read";

    // User
    [ObservableProperty] private string _newUserUsername  = string.Empty;
    [ObservableProperty] private string _newUserFirstName = string.Empty;
    [ObservableProperty] private string _newUserLastName  = string.Empty;

    public event EventHandler? GoBack;

    private Guid VaultId =>
        Guid.Parse(_credentials.Get(AppConfig.VaultIdKey)
                   ?? _config["Vault:VaultId"]
                   ?? Guid.Empty.ToString());

    public AdminViewModel(VaultApiClient api, CredentialStore credentials, IConfiguration config)
    {
        _api         = api;
        _credentials = credentials;
        _config      = config;
    }

    // ── Carregamento ───────────────────────────────────────────────────────

    [RelayCommand]
    private async Task LoadAsync()
    {
        IsBusy = true;
        StatusMessage = string.Empty;

        try
        {
            await Task.WhenAll(
                LoadSecretsInternalAsync(),
                LoadAdMapsInternalAsync(),
                LoadUsersInternalAsync());
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erro ao carregar dados: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadSecretsInternalAsync()
    {
        var items = await _api.ListSecretsAsync(VaultId);
        Secrets.Clear();
        foreach (var item in items) Secrets.Add(item);
    }

    private async Task LoadAdMapsInternalAsync()
    {
        var items = await _api.ListAdMapsAsync(VaultId);
        AdMaps.Clear();
        foreach (var item in items) AdMaps.Add(item);
    }

    private async Task LoadUsersInternalAsync()
    {
        try
        {
            var items = await _api.ListUsersAsync();
            Users.Clear();
            foreach (var item in items) Users.Add(item);
        }
        catch
        {
            // endpoint pode não existir ainda — ignora silenciosamente
        }
    }

    // ── Secrets ────────────────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanCreateSecret))]
    private async Task CreateSecretAsync()
    {
        IsBusy = true;
        try
        {
            await _api.UpsertSecretAsync(VaultId, NewSecretName.Trim(), NewSecretValue,
                string.IsNullOrWhiteSpace(NewSecretContentType) ? null : NewSecretContentType.Trim());

            StatusMessage = $"Segredo '{NewSecretName}' criado/atualizado.";
            NewSecretName = NewSecretValue = NewSecretContentType = string.Empty;
            await LoadSecretsInternalAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erro: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    private bool CanCreateSecret()
        => !IsBusy
           && !string.IsNullOrWhiteSpace(NewSecretName)
           && !string.IsNullOrWhiteSpace(NewSecretValue);

    [RelayCommand]
    private async Task DeleteSecretAsync(SecretItem? secret)
    {
        if (secret is null) return;
        IsBusy = true;
        try
        {
            await _api.DeleteSecretAsync(VaultId, secret.Name);
            StatusMessage = $"Segredo '{secret.Name}' desativado.";
            await LoadSecretsInternalAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erro: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    // ── AD Maps ────────────────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanCreateAdMap))]
    private async Task CreateAdMapAsync()
    {
        IsBusy = true;
        try
        {
            await _api.CreateAdMapAsync(VaultId, NewAdMapGroupId.Trim(), NewAdMapPermission);
            StatusMessage = $"AD Map '{NewAdMapGroupId}' criado.";
            NewAdMapGroupId = string.Empty;
            await LoadAdMapsInternalAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erro: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    private bool CanCreateAdMap()
        => !IsBusy && !string.IsNullOrWhiteSpace(NewAdMapGroupId);

    [RelayCommand]
    private async Task DeleteAdMapAsync(AdMapItem? adMap)
    {
        if (adMap is null) return;
        IsBusy = true;
        try
        {
            await _api.DeleteAdMapAsync(VaultId, adMap.Id);
            StatusMessage = $"AD Map '{adMap.GroupId}' removido.";
            await LoadAdMapsInternalAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erro: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    // ── Users ──────────────────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanCreateUser))]
    private async Task CreateUserAsync(string? password)
    {
        if (string.IsNullOrWhiteSpace(password)) return;
        IsBusy = true;
        try
        {
            await _api.RegisterUserAsync(
                NewUserUsername.Trim(), password,
                NewUserFirstName.Trim(), NewUserLastName.Trim());

            StatusMessage = $"Usuário '{NewUserUsername}' criado.";
            NewUserUsername = NewUserFirstName = NewUserLastName = string.Empty;
            await LoadUsersInternalAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erro: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    private bool CanCreateUser(string? password)
        => !IsBusy
           && !string.IsNullOrWhiteSpace(NewUserUsername)
           && !string.IsNullOrWhiteSpace(password);

    // ── Navegação ──────────────────────────────────────────────────────────

    [RelayCommand]
    private void BackToSecrets() => GoBack?.Invoke(this, EventArgs.Empty);

    // Notifica CanExecute quando campos mudam
    partial void OnNewSecretNameChanged(string value) => CreateSecretCommand.NotifyCanExecuteChanged();
    partial void OnNewSecretValueChanged(string value) => CreateSecretCommand.NotifyCanExecuteChanged();
    partial void OnNewAdMapGroupIdChanged(string value) => CreateAdMapCommand.NotifyCanExecuteChanged();
    partial void OnNewUserUsernameChanged(string value) => CreateUserCommand.NotifyCanExecuteChanged();
}
