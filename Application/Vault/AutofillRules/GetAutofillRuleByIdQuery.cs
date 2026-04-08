using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AutofillRules;

public sealed record GetAutofillRuleByIdQuery(Guid VaultId, Guid RuleId) : IQuery<AutofillRuleDto>;

public sealed class GetAutofillRuleByIdQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetAutofillRuleByIdQuery, AutofillRuleDto>
{
    public async Task<Result<AutofillRuleDto>> Handle(GetAutofillRuleByIdQuery query, CancellationToken cancellationToken = default)
    {
        var item = await dbContext.AutofillRules
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId && x.Id == query.RuleId)
            .Select(x => new AutofillRuleDto(
                x.Id,
                x.VaultId,
                x.UrlPattern,
                x.Login,
                x.SecretName,
                x.IsActive,
                x.CreatedAt))
            .SingleOrDefaultAsync(cancellationToken);

        return item is null
            ? Result.Failure<AutofillRuleDto>(VaultErrors.AutofillRuleNotFound(query.VaultId, query.RuleId))
            : item;
    }
}
