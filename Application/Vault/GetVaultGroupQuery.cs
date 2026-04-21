using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault;

public sealed record GetVaultGroupQuery(Guid VaultId) : IQuery<string>;

internal sealed class GetVaultGroupQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetVaultGroupQuery, string>
{
    public async Task<Result<string>> Handle(GetVaultGroupQuery query, CancellationToken cancellationToken = default)
    {
        var vault = await dbContext.Vaults
            .AsNoTracking()
            .Where(x => x.Id == query.VaultId)
            .Select(x => new { x.Id, x.Group })
            .SingleOrDefaultAsync(cancellationToken);

        if (vault is null)
        {
            return Result.Failure<string>(VaultErrors.VaultNotFound(query.VaultId));
        }

        if (string.IsNullOrWhiteSpace(vault.Group))
        {
            return Result.Failure<string>(VaultErrors.VaultMissingGroup(query.VaultId));
        }

        return vault.Group;
    }
}

/// <summary>
/// Contexto de autorização de um cofre: grupo AD "dono" (<c>Group</c>) e identificador
/// do tenant (<c>TenantId</c>). Usado para decidir permissões hierárquicas:
/// Admin Geral &gt; Admin de Cofre (admin-vault-{TenantId}) &gt; membros do <c>Group</c>.
/// </summary>
public sealed record VaultAuthContext(string Group, string TenantId);

/// <summary>
/// Retorna <see cref="VaultAuthContext"/> para um cofre num único round-trip —
/// evita duas queries quando o endpoint precisa checar tanto Admin Geral quanto
/// Admin de Cofre.
/// </summary>
public sealed record GetVaultAuthContextQuery(Guid VaultId) : IQuery<VaultAuthContext>;

internal sealed class GetVaultAuthContextQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetVaultAuthContextQuery, VaultAuthContext>
{
    public async Task<Result<VaultAuthContext>> Handle(GetVaultAuthContextQuery query, CancellationToken cancellationToken = default)
    {
        var vault = await dbContext.Vaults
            .AsNoTracking()
            .Where(x => x.Id == query.VaultId)
            .Select(x => new { x.Group, x.TenantId })
            .SingleOrDefaultAsync(cancellationToken);

        if (vault is null)
        {
            return Result.Failure<VaultAuthContext>(VaultErrors.VaultNotFound(query.VaultId));
        }

        if (string.IsNullOrWhiteSpace(vault.Group))
        {
            return Result.Failure<VaultAuthContext>(VaultErrors.VaultMissingGroup(query.VaultId));
        }

        // TenantId é NOT NULL no schema (VaultConfiguration) — checagem defensiva para
        // cofres legados ou inseridos manualmente sem tenant.
        if (string.IsNullOrWhiteSpace(vault.TenantId))
        {
            return Result.Failure<VaultAuthContext>(VaultErrors.VaultNotFound(query.VaultId));
        }

        return new VaultAuthContext(vault.Group, vault.TenantId);
    }
}
