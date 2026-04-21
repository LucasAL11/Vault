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

    public ObservableCollection<SecretItem>       Secrets       { get; } = [];
    public ObservableCollection<AdMapItem>        AdMaps        { get; } = [];
    public ObservableCollection<UserItem>         Users         { get; } = [];
    public ObservableCollection<VaultItem>        Vaults        { get; } = [];
    public ObservableCollection<AutofillRuleItem> AutofillRules { get; } = [];

    [ObservableProperty] private bool   _isBusy;
    [ObservableProperty] private string _statusMessage = string.Empty;
    [ObservableProperty] private string _statusType    = "info"; // "info", "success", "error"

    /// <summary>
    /// True when the logged-in user is Admin Geral (has an AD group containing "Admin").
    /// Controls visibility of global-only features: Users tab, Novo Cofre button.
    /// Vault admins (admin-vault-{tenant}) see only vault-scoped tabs.
    /// </summary>
    [ObservableProperty] private bool _isGlobalAdmin;

    // ── Layout state ──────────────────────────────────────────────────────
    [ObservableProperty] private int _selectedTab; // 0=Secrets, 1=AD Maps, 2=Users, 3=Autofill

    /// <summary>The currently selected vault in the sidebar.</summary>
    [ObservableProperty] private VaultItem? _selectedVault;

    /// <summary>Controls whether the create-vault form is shown instead of tabs.</summary>
    [ObservableProperty] private bool _showCreateVaultForm;

    /// <summary>Controls whether the edit-vault form is shown.</summary>
    [ObservableProperty] private bool _showEditVaultForm;

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

    // Vault editing
    [ObservableProperty] private string _editVaultName        = string.Empty;
    [ObservableProperty] private string _editVaultDescription = string.Empty;

    // Secret creation / editing
    [ObservableProperty] private string _newSecretName        = string.Empty;
    [ObservableProperty] private string _newSecretValue       = string.Empty;
    [ObservableProperty] private string _newSecretContentType = string.Empty;

    /// <summary>True when editing an existing secret (name is read-only).</summary>
    [ObservableProperty] private bool _isEditingSecret;

    // AD Map creation
    [ObservableProperty] private string _newAdMapGroupId   = string.Empty;
    [ObservableProperty] private string _newAdMapPermission = "Read";

    // User creation
    [ObservableProperty] private string _newUserUsername  = string.Empty;
    [ObservableProperty] private string _newUserFirstName = string.Empty;
    [ObservableProperty] private string _newUserLastName  = string.Empty;

    // Autofill rule creation / editing
    [ObservableProperty] private string _newRuleUrlPattern = string.Empty;
    [ObservableProperty] private string _newRuleLogin      = string.Empty;
    [ObservableProperty] private string _newRuleSecretName = string.Empty;

    /// <summary>True when editing an existing autofill rule.</summary>
    [ObservableProperty] private bool _isEditingRule;
    private Guid _editingRuleId;

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
            ShowEditVaultForm   = false;
            _credentials.Set(AppConfig.VaultIdKey, value.Id.ToString());
            _ = LoadVaultContentAsync();
        }
    }

    partial void OnShowCreateVaultFormChanged(bool value)
    {
        if (value)
        {
            ShowEditVaultForm = false;
            // Clear form when opening
            NewVaultName = NewVaultSlug = NewVaultDescription =
                NewVaultTenantId = NewVaultGroup = string.Empty;
            NewVaultEnvironment = "Production";
            _slugManuallyEdited = false;
        }
    }

    partial void OnShowEditVaultFormChanged(bool value)
    {
        if (value && SelectedVault is not null)
        {
            ShowCreateVaultForm = false;
            EditVaultName        = SelectedVault.Name;
            EditVaultDescription = SelectedVault.Description;
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

    partial void OnNewVaultTenantIdChanged(string value)    => CreateVaultCommand.NotifyCanExecuteChanged();
    partial void OnNewVaultGroupChanged(string value)       => CreateVaultCommand.NotifyCanExecuteChanged();
    partial void OnEditVaultNameChanged(string value)       => SaveVaultCommand.NotifyCanExecuteChanged();
    partial void OnNewSecretNameChanged(string value)       => CreateSecretCommand.NotifyCanExecuteChanged();
    partial void OnNewSecretValueChanged(string value)      => CreateSecretCommand.NotifyCanExecuteChanged();
    partial void OnNewAdMapGroupIdChanged(string value)     => CreateAdMapCommand.NotifyCanExecuteChanged();
    partial void OnNewUserUsernameChanged(string value)     => CreateUserCommand.NotifyCanExecuteChanged();
    partial void OnNewRuleUrlPatternChanged(string value)   => CreateAutofillRuleCommand.NotifyCanExecuteChanged();
    partial void OnNewRuleLoginChanged(string value)        => CreateAutofillRuleCommand.NotifyCanExecuteChanged();
    partial void OnNewRuleSecretNameChanged(string value)   => CreateAutofillRuleCommand.NotifyCanExecuteChanged();

    // ── Carregamento ───────────────────────────────────────────────────────

    [RelayCommand]
    private async Task LoadAsync()
    {
        IsBusy = true;
        StatusMessage = string.Empty;

        try
        {
            var tasks = new List<Task> { LoadVaultsInternalAsync() };
            if (IsGlobalAdmin)
                tasks.Add(LoadUsersInternalAsync());
            await Task.WhenAll(tasks);

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

    /// <summary>Loads secrets + AD maps + autofill rules for the currently selected vault.</summary>
    private async Task LoadVaultContentAsync()
    {
        if (SelectedVault is null) return;
        IsBusy = true;
        try
        {
            await Task.WhenAll(
                LoadSecretsInternalAsync(),
                LoadAdMapsInternalAsync(),
                LoadAutofillRulesInternalAsync());
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

    private async Task LoadAutofillRulesInternalAsync()
    {
        try
        {
            var items = await _api.ListAutofillRulesAsync(VaultId);
            AutofillRules.Clear();
            foreach (var item in items) AutofillRules.Add(item);
        }
        catch { /* ignore if endpoint unavailable */ }
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

    [RelayCommand]
    private void OpenEditVaultForm()
    {
        ShowEditVaultForm = true;
    }

    [RelayCommand]
    private void CancelEditVault()
    {
        ShowEditVaultForm = false;
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

    [RelayCommand(CanExecute = nameof(CanSaveVault))]
    private async Task SaveVaultAsync()
    {
        if (SelectedVault is null) return;
        IsBusy = true;
        try
        {
            await _api.UpdateVaultAsync(SelectedVault.Id, EditVaultName.Trim(), EditVaultDescription.Trim());

            SetStatus($"Cofre atualizado com sucesso!", "success");
            ShowEditVaultForm = false;

            // Refresh vault list and re-select
            var previousId = SelectedVault.Id;
            await LoadVaultsInternalAsync();
            var updated = Vaults.FirstOrDefault(v => v.Id == previousId);
            if (updated is not null)
                SelectedVault = updated;
        }
        catch (Exception ex)
        {
            SetStatus($"Erro ao atualizar cofre: {ex.Message}", "error");
        }
        finally { IsBusy = false; }
    }

    private bool CanSaveVault()
        => !IsBusy && !string.IsNullOrWhiteSpace(EditVaultName);

    [RelayCommand]
    private async Task DeleteVaultAsync()
    {
        if (SelectedVault is null) return;
        IsBusy = true;
        try
        {
            var hardDeleted = await _api.DeleteVaultAsync(SelectedVault.Id);
            var msg = hardDeleted
                ? $"Cofre '{SelectedVault.Name}' excluído permanentemente."
                : $"Cofre '{SelectedVault.Name}' desativado (contém segredos ativos).";
            SetStatus(msg, "success");

            SelectedVault = null;
            await LoadVaultsInternalAsync();

            if (Vaults.Count > 0)
                SelectedVault = Vaults[0];
        }
        catch (Exception ex)
        {
            SetStatus($"Erro ao excluir cofre: {ex.Message}", "error");
        }
        finally { IsBusy = false; }
    }

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

            var verb = IsEditingSecret ? "atualizado" : "criado";
            SetStatus($"Segredo '{NewSecretName}' {verb}.", "success");
            IsEditingSecret = false;
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
    private void EditSecret(SecretItem? secret)
    {
        if (secret is null) return;
        NewSecretName        = secret.Name;
        NewSecretValue       = string.Empty;
        NewSecretContentType = secret.ContentType ?? string.Empty;
        IsEditingSecret      = true;
    }

    [RelayCommand]
    private void CancelEditSecret()
    {
        IsEditingSecret      = false;
        NewSecretName        = string.Empty;
        NewSecretValue       = string.Empty;
        NewSecretContentType = string.Empty;
    }

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

    // ── Autofill Rules ────────────────────────────────────────────────────

    [RelayCommand]
    private void EditAutofillRule(AutofillRuleItem? rule)
    {
        if (rule is null) return;
        _editingRuleId     = rule.Id;
        NewRuleUrlPattern  = rule.UrlPattern;
        NewRuleLogin       = rule.Login;
        NewRuleSecretName  = rule.SecretName;
        IsEditingRule      = true;
    }

    [RelayCommand]
    private void CancelEditRule()
    {
        IsEditingRule     = false;
        _editingRuleId    = Guid.Empty;
        NewRuleUrlPattern = NewRuleLogin = NewRuleSecretName = string.Empty;
    }

    [RelayCommand(CanExecute = nameof(CanCreateAutofillRule))]
    private async Task CreateAutofillRuleAsync()
    {
        IsBusy = true;
        try
        {
            if (IsEditingRule)
            {
                await _api.UpdateAutofillRuleAsync(
                    VaultId, _editingRuleId,
                    NewRuleUrlPattern.Trim(),
                    NewRuleLogin.Trim(),
                    NewRuleSecretName.Trim(),
                    isActive: true);
                SetStatus($"Regra para '{NewRuleUrlPattern}' atualizada.", "success");
            }
            else
            {
                await _api.CreateAutofillRuleAsync(
                    VaultId,
                    NewRuleUrlPattern.Trim(),
                    NewRuleLogin.Trim(),
                    NewRuleSecretName.Trim());
                SetStatus($"Regra para '{NewRuleUrlPattern}' criada.", "success");
            }

            IsEditingRule = false;
            _editingRuleId = Guid.Empty;
            NewRuleUrlPattern = NewRuleLogin = NewRuleSecretName = string.Empty;
            await LoadAutofillRulesInternalAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}", "error");
        }
        finally { IsBusy = false; }
    }

    private bool CanCreateAutofillRule()
        => !IsBusy
           && !string.IsNullOrWhiteSpace(NewRuleUrlPattern)
           && !string.IsNullOrWhiteSpace(NewRuleLogin)
           && !string.IsNullOrWhiteSpace(NewRuleSecretName);

    [RelayCommand]
    private async Task DeleteAutofillRuleAsync(AutofillRuleItem? rule)
    {
        if (rule is null) return;
        IsBusy = true;
        try
        {
            await _api.DeleteAutofillRuleAsync(VaultId, rule.Id);
            SetStatus($"Regra removida.", "success");
            await LoadAutofillRulesInternalAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}", "error");
        }
        finally { IsBusy = false; }
    }

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
