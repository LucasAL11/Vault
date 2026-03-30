using Microsoft.Extensions.Options;
using Shared.Integrity;

namespace Api.Endpoints.Operations;

/// <summary>
/// Level 3: Remote attestation endpoint.
/// Clients report their binary integrity status; the server decides
/// whether to allow, warn, or block the client.
/// </summary>
public sealed class IntegrityAttestationEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/ops/integrity")
            .WithTags("Integrity");

        group.MapPost("/attest", HandleAttest)
            .AllowAnonymous();

        group.MapGet("/manifest/{version}", HandleGetManifest)
            .RequireAuthorization("OperatorsGroup");

        group.MapPut("/manifest/{version}", HandlePutManifest)
            .RequireAuthorization("OperatorsGroup");
    }

    private static IResult HandleAttest(
        AttestationRequest request,
        IOptions<IntegrityAttestationOptions> options,
        ILogger<IntegrityAttestationEndpoint> logger)
    {
        var config = options.Value;

        logger.LogInformation(
            "Integrity attestation: client={ClientId} hwid={Hwid} version={Version} passed={Passed} violations={Count}",
            request.ClientId, request.Hwid, request.AssemblyVersion,
            request.LocalVerificationPassed, request.Violations.Count);

        // Disabled → always allow
        if (!config.Enabled)
        {
            return Results.Ok(new AttestationResponse
            {
                Allowed = true,
                Reason = "Attestation disabled.",
                Action = "allow"
            });
        }

        // Client failed local verification
        if (!request.LocalVerificationPassed)
        {
            logger.LogWarning(
                "Client {ClientId} FAILED integrity: {ErrorCode}. Violations: {Violations}",
                request.ClientId, request.ErrorCode,
                string.Join(", ", request.Violations.Select(v => $"{v.Type}:{v.FilePath}")));

            var action = config.OnFailure?.ToLowerInvariant() ?? "warn";
            return Results.Ok(new AttestationResponse
            {
                Allowed = action is not ("block" or "kill"),
                Reason = $"Local integrity failed: {request.ErrorCode}",
                Action = action
            });
        }

        // Check trusted manifest hash
        if (config.TrustedManifestHashes.Count > 0)
        {
            var key = $"{request.AssemblyName}:{request.AssemblyVersion}";

            if (config.TrustedManifestHashes.TryGetValue(key, out var trustedHash))
            {
                if (!string.Equals(request.ManifestHash, trustedHash, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogCritical(
                        "ATTESTATION MISMATCH: {ClientId} v{Version} hash {Actual} != {Expected}",
                        request.ClientId, request.AssemblyVersion,
                        request.ManifestHash, trustedHash);

                    return Results.Ok(new AttestationResponse
                    {
                        Allowed = false,
                        Reason = "Manifest hash mismatch. Binary may be tampered.",
                        Action = "kill"
                    });
                }
            }
            else if (config.RejectUnknownVersions)
            {
                return Results.Ok(new AttestationResponse
                {
                    Allowed = false,
                    Reason = $"Version {request.AssemblyVersion} is not registered.",
                    Action = "block"
                });
            }
        }

        return Results.Ok(new AttestationResponse
        {
            Allowed = true,
            Reason = "Integrity verified.",
            Action = "allow"
        });
    }

    private static IResult HandleGetManifest(
        string version,
        IOptions<IntegrityAttestationOptions> options)
    {
        var config = options.Value;
        var key = config.TrustedManifestHashes.Keys
            .FirstOrDefault(k => k.EndsWith($":{version}", StringComparison.OrdinalIgnoreCase));

        return key is null
            ? Results.NotFound(new { message = $"No trusted manifest for version {version}" })
            : Results.Ok(new { version, manifestHash = config.TrustedManifestHashes[key] });
    }

    private static IResult HandlePutManifest(
        string version,
        RegisterManifestRequest request,
        IOptions<IntegrityAttestationOptions> options,
        ILogger<IntegrityAttestationEndpoint> logger)
    {
        var config = options.Value;
        var key = $"{request.AssemblyName}:{version}";
        config.TrustedManifestHashes[key] = request.ManifestHash;

        logger.LogInformation("Registered trusted manifest: {Key} = {Hash}", key, request.ManifestHash);

        return Results.Ok(new { registered = key, hash = request.ManifestHash });
    }
}

public sealed class RegisterManifestRequest
{
    public string AssemblyName { get; set; } = string.Empty;
    public string ManifestHash { get; set; } = string.Empty;
}

public sealed class IntegrityAttestationOptions
{
    public bool Enabled { get; set; } = false;
    public string OnFailure { get; set; } = "warn";
    public bool RejectUnknownVersions { get; set; } = false;
    public Dictionary<string, string> TrustedManifestHashes { get; set; } = new();
}
