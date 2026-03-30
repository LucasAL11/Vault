using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault;

public sealed record CreateVaultCommand(
    string Name,
    string Slug,
    string Description,
    string TenantId,
    string Group,
    Domain.vault.Environment Environment,
    string Actor) : ICommand<CreateVaultResultDto>;

public sealed record CreateVaultResultDto(Guid Id, string Name, string Slug);

public sealed class CreateVaultCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<CreateVaultCommand, CreateVaultResultDto>
{
    public async Task<Result<CreateVaultResultDto>> Handle(
        CreateVaultCommand command, CancellationToken cancellationToken = default)
    {
        var slugExists = await dbContext.Vaults
            .AnyAsync(v => v.Slug == command.Slug, cancellationToken);

        if (slugExists)
            return Result.Failure<CreateVaultResultDto>(
                VaultErrors.SlugAlreadyExists(command.Slug));

        var vault = new Domain.vault.Vault(
            command.TenantId,
            command.Name,
            command.Slug,
            command.Group,
            command.Environment);

        vault.UpdateDescription(command.Description ?? string.Empty, command.Actor);
        vault.Status = Status.Active;

        await dbContext.Vaults.AddAsync(vault, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return new CreateVaultResultDto(vault.Id, vault.Name, vault.Slug);
    }
}
