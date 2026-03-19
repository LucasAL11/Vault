using Application.Abstractions.Security;

namespace Api.Endpoints.Diagnostics;

public sealed class KeyProviderDebug : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/debug/key-provider", async (IKeyProvider keyProvider, CancellationToken cancellationToken) =>
        {
            var key = await keyProvider.GetCurrentKeyAsync(cancellationToken);
            var knownIds = await keyProvider.GetKnownKeyIdsAsync(cancellationToken);
            return Results.Ok(new
            {
                key.KeyId,
                KeyLength = key.KeyBytes.Length,
                KnownKeyIds = knownIds
            });
        }).RequireAuthorization();
    }
}
