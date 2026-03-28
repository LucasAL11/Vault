using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault;
using Shared;

namespace Api.Endpoints.Vault;

public class VaultCreateEndpoint : IEndpoint
{
    private record Request(
        string Name,
        string Slug,
        string? Description,
        string TenantId,
        string Group,
        string? Environment);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/vaults", async (
            Request request,
            IMessageDispatcher sender,
            IUserContext user) =>
        {
            if (!Enum.TryParse<Domain.vault.Environment>(
                    request.Environment ?? "Production", true, out var env))
                env = Domain.vault.Environment.Production;

            var command = new CreateVaultCommand(
                request.Name,
                request.Slug,
                request.Description ?? string.Empty,
                request.TenantId,
                request.Group,
                env,
                Actor: user.Identity.Username);

            Result<CreateVaultResultDto> result = await sender.Send(command);

            return result.Match(
                dto => Results.Created($"/vaults/{dto.Id}", dto),
                CustomResults.Problem);
        }).RequireAuthorization();
    }
}
