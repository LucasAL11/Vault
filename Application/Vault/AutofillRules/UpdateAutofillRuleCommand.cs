using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AutofillRules;

public sealed record UpdateAutofillRuleCommand(
    Guid VaultId,
    Guid RuleId,
    string UrlPattern,
    string Login,
    string SecretName,
    bool IsActive) : ICommand<AutofillRuleDto>;

public sealed class UpdateAutofillRuleCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<UpdateAutofillRuleCommand, AutofillRuleDto>
{
    public async Task<Result<AutofillRuleDto>> Handle(UpdateAutofillRuleCommand command, CancellationToken cancellationToken = default)
    {
        var rule = await dbContext.AutofillRules
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Id == command.RuleId, cancellationToken);

        if (rule is null)
        {
            return Result.Failure<AutofillRuleDto>(VaultErrors.AutofillRuleNotFound(command.VaultId, command.RuleId));
        }

        rule.Update(command.UrlPattern, command.Login, command.SecretName);

        if (command.IsActive)
        {
            rule.Enable();
        }
        else
        {
            rule.Disable();
        }

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
