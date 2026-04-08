using Application.Abstractions.Data;
using Microsoft.EntityFrameworkCore;

namespace Application.Vault.Secrets;

internal static class DbProviderCompatibility
{
    public static bool IsSqliteProvider(IApplicationDbContext dbContext)
    {
        return dbContext is DbContext efDb &&
               string.Equals(efDb.Database.ProviderName, "Microsoft.EntityFrameworkCore.Sqlite", StringComparison.Ordinal);
    }
}
