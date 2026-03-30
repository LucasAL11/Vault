using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace Shared.Integrity;

/// <summary>
/// Client-side: sends integrity attestation to the server for validation.
/// The server keeps a registry of expected manifests per version
/// and can reject clients with tampered binaries.
/// </summary>
public sealed class IntegrityAttestationClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public IntegrityAttestationClient(HttpClient http, string baseUrl)
    {
        _http = http;
        _baseUrl = baseUrl.TrimEnd('/');
    }

    /// <summary>
    /// Sends the local integrity result to the server for remote validation.
    /// Returns the server's attestation decision.
    /// </summary>
    public async Task<AttestationResponse> AttestAsync(
        IntegrityResult localResult,
        string clientId,
        string hwid,
        CancellationToken ct = default)
    {
        var request = new AttestationRequest
        {
            ClientId = clientId,
            Hwid = hwid,
            AssemblyName = localResult.Manifest?.AssemblyName ?? "Unknown",
            AssemblyVersion = localResult.Manifest?.AssemblyVersion ?? "0.0.0",
            LocalVerificationPassed = localResult.IsValid,
            ErrorCode = localResult.ErrorCode,
            FileCount = localResult.Manifest?.Files.Count ?? 0,
            ManifestHash = localResult.Manifest is not null
                ? IntegrityHasher.HashBytes(
                    System.Text.Encoding.UTF8.GetBytes(localResult.Manifest.BuildCanonicalPayload()))
                : null,
            Violations = localResult.Violations.Select(v => new AttestationViolation
            {
                FilePath = v.FilePath,
                Type = v.Type.ToString(),
                ExpectedHash = v.ExpectedHash,
                ActualHash = v.ActualHash
            }).ToList(),
            Timestamp = DateTimeOffset.UtcNow
        };

        var response = await _http.PostAsJsonAsync(
            $"{_baseUrl}/ops/integrity/attest", request, ct);

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<AttestationResponse>(ct)
            ?? throw new InvalidOperationException("Empty attestation response.");
    }
}

public sealed class AttestationRequest
{
    [JsonPropertyName("clientId")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("hwid")]
    public string Hwid { get; set; } = string.Empty;

    [JsonPropertyName("assemblyName")]
    public string AssemblyName { get; set; } = string.Empty;

    [JsonPropertyName("assemblyVersion")]
    public string AssemblyVersion { get; set; } = string.Empty;

    [JsonPropertyName("localVerificationPassed")]
    public bool LocalVerificationPassed { get; set; }

    [JsonPropertyName("errorCode")]
    public string? ErrorCode { get; set; }

    [JsonPropertyName("fileCount")]
    public int FileCount { get; set; }

    [JsonPropertyName("manifestHash")]
    public string? ManifestHash { get; set; }

    [JsonPropertyName("violations")]
    public List<AttestationViolation> Violations { get; set; } = [];

    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; set; }
}

public sealed class AttestationViolation
{
    [JsonPropertyName("filePath")]
    public string FilePath { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("expectedHash")]
    public string? ExpectedHash { get; set; }

    [JsonPropertyName("actualHash")]
    public string? ActualHash { get; set; }
}

public sealed class AttestationResponse
{
    [JsonPropertyName("allowed")]
    public bool Allowed { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("action")]
    public string Action { get; set; } = "allow"; // allow, warn, block, kill
}
