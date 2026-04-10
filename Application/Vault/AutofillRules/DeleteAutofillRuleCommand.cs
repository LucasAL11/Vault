using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AutofillRules;

public sealed record DeleteAutofillRuleCommand(Guid VaultId, Guid RuleId) : ICommand<bool>;

internal sealed class DeleteAutofillRuleCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<DeleteAutofillRuleCommand, bool>
{
    public async Task<Result<bool>> Handle(DeleteAutofillRuleCommand command, CancellationToken cancellationToken = default)
    {
        var rule = await dbContext.AutofillRules
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Id == command.RuleId, cancellationToken);

        if (rule is null)
        {
            return Result.Failure<bool>(VaultErrors.AutofillRuleNotFound(command.VaultId, command.RuleId));
        }

        dbContext.AutofillRules.Remove(rule);
        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }
}
