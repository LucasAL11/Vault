using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AutofillRules;

public sealed record ListAutofillRulesQuery(Guid VaultId, bool IncludeInactive)
    : IQuery<IReadOnlyCollection<AutofillRuleDto>>;

internal sealed class ListAutofillRulesQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<ListAutofillRulesQuery, IReadOnlyCollection<AutofillRuleDto>>
{
    public async Task<Result<IReadOnlyCollection<AutofillRuleDto>>> Handle(ListAutofillRulesQuery query, CancellationToken cancellationToken = default)
    {
        var baseQuery = dbContext.AutofillRules
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId);

        if (!query.IncludeInactive)
        {
            baseQuery = baseQuery.Where(x => x.IsActive);
        }

        var items = await baseQuery
            .Select(x => new AutofillRuleDto(
                x.Id,
                x.VaultId,
                x.UrlPattern,
                x.Login,
                x.SecretName,
                x.IsActive,
                x.CreatedAt))
            .ToListAsync(cancellationToken);

        return items
            .OrderByDescending(x => x.CreatedAt)
            .ToArray();
    }
}
