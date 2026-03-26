namespace Api.Endpoints.Vault.Secret;

internal static class SecretHttpHelpers
{
    internal static void ApplyNoStoreHeaders(this HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
    }

    internal static IResult SecureForbidden()
        => Results.Json(new { message = "Access denied." }, statusCode: StatusCodes.Status403Forbidden);

    internal static IResult SecureNotFound()
        => Results.NotFound(new { message = "Resource not available." });
}
