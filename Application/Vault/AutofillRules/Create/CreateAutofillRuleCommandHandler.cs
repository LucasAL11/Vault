using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AutofillRules.Create;

internal sealed class CreateAutofillRuleCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<CreateAutofillRuleCommand, AutofillRuleDto>
{
    public async Task<Result<AutofillRuleDto>> Handle(CreateAutofillRuleCommand command, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.UrlPattern))
        {
            return Result.Failure<AutofillRuleDto>(VaultErrors.InvalidUrlPattern());
        }

        if (string.IsNullOrWhiteSpace(command.Login))
        {
            return Result.Failure<AutofillRuleDto>(VaultErrors.InvalidLogin());
        }

        if (string.IsNullOrWhiteSpace(command.SecretName))
        {
            return Result.Failure<AutofillRuleDto>(VaultErrors.InvalidSecretName());
        }

        var normalizedUrl = command.UrlPattern.Trim();
        var exists = await dbContext.AutofillRules
            .AsNoTracking()
            .AnyAsync(x => x.VaultId == command.VaultId && x.UrlPattern == normalizedUrl, cancellationToken);

        if (exists)
        {
            return Result.Failure<AutofillRuleDto>(VaultErrors.AutofillRuleAlreadyExists(command.VaultId, normalizedUrl));
        }

        var rule = new AutofillRule(command.VaultId, normalizedUrl, command.Login, command.SecretName);
        if (!command.IsActive)
        {
            rule.Disable();
        }

        await dbContext.AutofillRules.AddAsync(rule, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return new AutofillRuleDto(
            rule.Id,
            rule.VaultId,
            rule.UrlPattern,
            rule.Login,
            rule.SecretName,
            rule.IsActive,
            rule.CreatedAt);
    }
}
