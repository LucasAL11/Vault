using Api.Endpoints.Users;
using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Security;
using Application.Contracts.Zk;
using Application.Cryptography;
using Shared;

namespace Api.Endpoints.Cryptography;

public sealed class Prove : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapPost("/Cryptography/zk", async (
            PreimageRequest request,
            IMessageDispatcher sender,
            INonceStore nonceStore,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!TryFromBase64Url(request.Nonce, out var nonceBytes))
            {
                return Results.BadRequest(new { message = "nonce is invalid." });
            }

            var scope = NonceChallengeScope.Build(httpContext, request.ClientId);
            var consumed = await nonceStore.TryConsumeAsync(scope, nonceBytes, cancellationToken);
            if (!consumed)
            {
                return Results.Unauthorized();
            }

            var command = new ProveCommand(request);
            Result<string> result = await sender.Send(command, cancellationToken);

            return result.Match(Results.Ok, CustomResults.Problem);
        });
    }

    private static bool TryFromBase64Url(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var normalized = input.Replace('-', '+').Replace('_', '/');
        switch (normalized.Length % 4)
        {
            case 2:
                normalized += "==";
                break;
            case 3:
                normalized += "=";
                break;
            case 1:
                return false;
        }

        try
        {
            bytes = Convert.FromBase64String(normalized);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
