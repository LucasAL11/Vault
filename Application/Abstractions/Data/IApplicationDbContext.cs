using Domain.Computers;
using Domain.vault;
using Microsoft.EntityFrameworkCore;

namespace Application.Abstractions.Data;

public interface IApplicationDbContext
{
    DbSet<Computer>  Computers { get; }
    DbSet<Domain.vault.Vault>  Vaults { get; }
    DbSet<VaultMachine> VaultMachines { get; }
    DbSet<ADMap> ADMaps { get; }
    DbSet<AutofillRule> AutofillRules { get; }
    DbSet<Secret> Secrets { get; }
    DbSet<SecretVersion> SecretVersions { get; }
    DbSet<SecretAuditEntry> SecretAuditEntries { get; }
    DbSet<Domain.Users.User> Users { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
