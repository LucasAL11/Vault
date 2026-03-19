using System.Security.Cryptography;
using System.Text;

namespace Api.Endpoints.Cryptography;

public sealed class HashSecret : IEndpoint
{
    private sealed record Request(string Secret);

    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapPost("/Cryptography/hash", (Request request) =>
        {
            if (string.IsNullOrWhiteSpace(request.Secret))
            {
                return Results.BadRequest(new
                {
                    Error = "secret is required"
                });
            }

            byte[] secretBytes = Encoding.UTF8.GetBytes(request.Secret);
            byte[] hashBytes = SHA256.HashData(secretBytes);
            string hashBase64 = Convert.ToBase64String(hashBytes);
            string hashHex = Convert.ToHexString(hashBytes).ToLowerInvariant();

            return Results.Ok(new
            {
                HashBase64 = hashBase64,
                HashHex = hashHex
            });
        });
    }
}
