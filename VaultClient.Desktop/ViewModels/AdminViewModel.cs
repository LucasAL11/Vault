using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
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
    public ObservableCollection<VaultItem>  Vaults  { get; } = [];

    [ObservableProperty] private bool   _isBusy;
    [ObservableProperty] private string _statusMessage = string.Empty;
    [ObservableProperty] private string _statusType    = "info"; // "info", "success", "error"

    // ── Layout state ──────────────────────────────────────────────────────
    [ObservableProperty] private int _selectedTab; // 0=Secrets, 1=AD Maps, 2=Users

    /// <summary>The currently selected vault in the sidebar.</summary>
    [ObservableProperty] private VaultItem? _selectedVault;

    /// <summary>Controls whether the create-vault form is shown instead of tabs.</summary>
    [ObservableProperty] private bool _showCreateVaultForm;

    /// <summary>Controls whether the create-vault form is in expanded/editing mode.</summary>
    [ObservableProperty] private bool _isEditingVault;

    // ── Formulários ────────────────────────────────────────────────────────

    // Vault creation
    [ObservableProperty] private string _newVaultName        = string.Empty;
    [ObservableProperty] private string _newVaultSlug        = string.Empty;
    [ObservableProperty] private string _newVaultDescription = string.Empty;
    [ObservableProperty] private string _newVaultTenantId    = string.Empty;
    [ObservableProperty] private string _newVaultGroup       = string.Empty;
    [ObservableProperty] private string _newVaultEnvironment = "Production";
    private bool _slugManuallyEdited;

    // Secret creation
    [ObservableProperty] private string _newSecretName        = string.Empty;
    [ObservableProperty] private string _newSecretValue       = string.Empty;
    [ObservableProperty] private string _newSecretContentType = string.Empty;

    // AD Map creation
    [ObservableProperty] private string _newAdMapGroupId   = string.Empty;
    [ObservableProperty] private string _newAdMapPermission = "Read";

    // User creation
    [ObservableProperty] private string _newUserUsername  = string.Empty;
    [ObservableProperty] private string _newUserFirstName = string.Empty;
    [ObservableProperty] private string _newUserLastName  = string.Empty;

    // ── Computed helpers ──────────────────────────────────────────────────
    public bool HasSelectedVault => SelectedVault is not null;
    public string SelectedVaultDisplay => SelectedVault is not null
        ? $"{SelectedVault.Name}  ({SelectedVault.Environment})"
        : string.Empty;

    public event EventHandler? GoBack;

    private Guid VaultId
    {
        get
        {
            if (SelectedVault is not null) return SelectedVault.Id;
            return Guid.TryParse(_credentials.Get(AppConfig.VaultIdKey) ?? _config["Vault:VaultId"], out var id)
                ? id
                : Guid.Empty;
        }
    }

    public AdminViewModel(VaultApiClient api, CredentialStore credentials, IConfiguration config)
    {
        _api         = api;
        _credentials = credentials;
        _config      = config;
    }

    // ── Property change handlers ──────────────────────────────────────────

    partial void OnSelectedVaultChanged(VaultItem? value)
    {
        OnPropertyChanged(nameof(HasSelectedVault));
        OnPropertyChanged(nameof(SelectedVaultDisplay));

        if (value is not null)
        {
            ShowCreateVaultForm = false;
            _credentials.Set(AppConfig.VaultIdKey, value.Id.ToString());
            _ = LoadVaultContentAsync();
        }
    }

    partial void OnShowCreateVaultFormChanged(bool value)
    {
        if (value)
        {
            // Clear form when opening
            NewVaultName = NewVaultSlug = NewVaultDescription =
                NewVaultTenantId = NewVaultGroup = string.Empty;
            NewVaultEnvironment = "Production";
            _slugManuallyEdited = false;
        }
    }

    // Auto-generate slug from name (unless user manually edited it)
    partial void OnNewVaultNameChanged(string value)
    {
        CreateVaultCommand.NotifyCanExecuteChanged();
        if (!_slugManuallyEdited && !string.IsNullOrWhiteSpace(value))
        {
            NewVaultSlug = GenerateSlug(value);
        }
    }

    partial void OnNewVaultSlugChanged(string value)
    {
        CreateVaultCommand.NotifyCanExecuteChanged();
        // Mark as manually edited if slug differs from auto-generated
        if (!string.IsNullOrWhiteSpace(NewVaultName))
        {
            var autoSlug = GenerateSlug(NewVaultName);
            if (value != autoSlug)
                _slugManuallyEdited = true;
        }
    }

    partial void OnNewVaultTenantIdChanged(string value) => CreateVaultCommand.NotifyCanExecuteChanged();
    partial void OnNewVaultGroupChanged(string value)    => CreateVaultCommand.NotifyCanExecuteChanged();
    partial void OnNewSecretNameChanged(string value)    => CreateSecretCommand.NotifyCanExecuteChanged();
    partial void OnNewSecretValueChanged(string value)   => CreateSecretCommand.NotifyCanExecuteChanged();
    partial void OnNewAdMapGroupIdChanged(string value)  => CreateAdMapCommand.NotifyCanExecuteChanged();
    partial void OnNewUserUsernameChanged(string value)  => CreateUserCommand.NotifyCanExecuteChanged();

    // ── Carregamento ───────────────────────────────────────────────────────

    [RelayCommand]
    private async Task LoadAsync()
    {
        IsBusy = true;
        StatusMessage = string.Empty;

        try
        {
            await Task.WhenAll(
                LoadVaultsInternalAsync(),
                LoadUsersInternalAsync());

            // Auto-select first vault or stored vault
            if (Vaults.Count > 0 && SelectedVault is null)
            {
                var storedId = _credentials.Get(AppConfig.VaultIdKey);
                var match = Guid.TryParse(storedId, out var id)
                    ? Vaults.FirstOrDefault(v => v.Id == id)
                    : null;
                SelectedVault = match ?? Vaults[0];
            }
        }
        catch (Exception ex)
        {
            SetStatus($"Erro ao carregar dados: {ex.Message}", "error");
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Loads secrets + AD maps for the currently selected vault.</summary>
    private async Task LoadVaultContentAsync()
    {
        if (SelectedVault is null) return;
        IsBusy = true;
        try
        {
            await Task.WhenAll(
                LoadSecretsInternalAsync(),
                LoadAdMapsInternalAsync());
        }
        catch (Exception ex)
        {
            SetStatus($"Erro ao carregar conteudo do cofre: {ex.Message}", "error");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadVaultsInternalAsync()
    {
        try
        {
            var items = await _api.ListVaultsAsync();
            Vaults.Clear();
            foreach (var item in items) Vaults.Add(item);
        }
        catch { /* endpoint may not exist yet */ }
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
        catch { /* endpoint may not exist yet */ }
    }

    // ── Sidebar actions ──────────────────────────────────────────────────

    [RelayCommand]
    private void OpenCreateVaultForm()
    {
        ShowCreateVaultForm = true;
    }

    [RelayCommand]
    private void CancelCreateVault()
    {
        ShowCreateVaultForm = false;
    }

    // ── Vaults ───────────────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanCreateVault))]
    private async Task CreateVaultAsync()
    {
        IsBusy = true;
        try
        {
            var id = await _api.CreateVaultAsync(
                NewVaultName.Trim(),
                NewVaultSlug.Trim(),
                NewVaultDescription.Trim(),
                NewVaultTenantId.Trim(),
                NewVaultGroup.Trim(),
                NewVaultEnvironment);

            SetStatus($"Cofre '{NewVaultName}' criado com sucesso!", "success");

            ShowCreateVaultForm = false;
            await LoadVaultsInternalAsync();

            // Auto-select the newly created vault
            var newVault = Vaults.FirstOrDefault(v => v.Id == id);
            if (newVault is not null)
                SelectedVault = newVault;
        }
        catch (Exception ex)
        {
            SetStatus($"Erro ao criar cofre: {ex.Message}", "error");
        }
        finally { IsBusy = false; }
    }

    private bool CanCreateVault()
        => !IsBusy
           && !string.IsNullOrWhiteSpace(NewVaultName)
           && !string.IsNullOrWhiteSpace(NewVaultSlug)
           && !string.IsNullOrWhiteSpace(NewVaultTenantId)
           && !string.IsNullOrWhiteSpace(NewVaultGroup);

    [RelayCommand]
    private void SelectVault(VaultItem? vault)
    {
        if (vault is null) return;
        SelectedVault = vault;
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

            SetStatus($"Segredo '{NewSecretName}' salvo.", "success");
            NewSecretName = NewSecretValue = NewSecretContentType = string.Empty;
            await LoadSecretsInternalAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}", "error");
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
            SetStatus($"Segredo '{secret.Name}' desativado.", "success");
            await LoadSecretsInternalAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}", "error");
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
            SetStatus($"Grupo '{NewAdMapGroupId}' vinculado ao cofre.", "success");
            NewAdMapGroupId = string.Empty;
            await LoadAdMapsInternalAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}", "error");
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
            SetStatus($"Grupo '{adMap.GroupId}' removido do cofre.", "success");
            await LoadAdMapsInternalAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}", "error");
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

            SetStatus($"Usuario '{NewUserUsername}' criado.", "success");
            NewUserUsername = NewUserFirstName = NewUserLastName = string.Empty;
            await LoadUsersInternalAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}", "error");
        }
        finally { IsBusy = false; }
    }

    private bool CanCreateUser(string? password)
        => !IsBusy
           && !string.IsNullOrWhiteSpace(NewUserUsername)
           && !string.IsNullOrWhiteSpace(password);

    // ── Navegacao ──────────────────────────────────────────────────────────

    [RelayCommand]
    private void BackToSecrets() => GoBack?.Invoke(this, EventArgs.Empty);

    // ── Helpers ─────────────────────────────────────────────────────────────

    private void SetStatus(string message, string type)
    {
        StatusMessage = message;
        StatusType = type;
    }

    private static string GenerateSlug(string name)
    {
        var slug = name.ToLowerInvariant().Trim();
        slug = Regex.Replace(slug, @"[^a-z0-9\s-]", "");
        slug = Regex.Replace(slug, @"\s+", "-");
        slug = Regex.Replace(slug, @"-+", "-");
        return slug.Trim('-');
    }
}
