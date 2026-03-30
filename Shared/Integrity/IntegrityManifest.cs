using System.Text.Json;
using System.Text.Json.Serialization;

namespace Shared.Integrity;

/// <summary>
/// Build-time manifest containing SHA-256 hashes of every assembly
/// and an Ed25519 signature over the sorted hash list.
/// Embedded as a resource or shipped alongside the binary.
/// </summary>
public sealed class IntegrityManifest
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("buildTimestamp")]
    public DateTimeOffset BuildTimestamp { get; set; }

    [JsonPropertyName("assemblyName")]
    public string AssemblyName { get; set; } = string.Empty;

    [JsonPropertyName("assemblyVersion")]
    public string AssemblyVersion { get; set; } = string.Empty;

    /// <summary>
    /// Dictionary of relative file path → SHA-256 hex hash.
    /// </summary>
    [JsonPropertyName("files")]
    public Dictionary<string, string> Files { get; set; } = new();

    /// <summary>
    /// Ed25519 signature (base64) over the canonical hash payload.
    /// </summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;

    /// <summary>
    /// Ed25519 public key (base64, 32 bytes) used to verify the signature.
    /// In production, this is hardcoded in the binary — not read from the manifest.
    /// Included here for tooling convenience only.
    /// </summary>
    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>
    /// Builds the canonical payload that is signed.
    /// Sorted file paths + hashes, one per line: "path=hash\n"
    /// Deterministic and tamper-evident.
    /// </summary>
    public string BuildCanonicalPayload()
    {
        var sorted = Files.OrderBy(kv => kv.Key, StringComparer.Ordinal);
        return string.Join('\n', sorted.Select(kv => $"{kv.Key}={kv.Value}"));
    }

    public string ToJson() =>
        JsonSerializer.Serialize(this, ManifestJsonContext.Default.IntegrityManifest);

    public static IntegrityManifest? FromJson(string json) =>
        JsonSerializer.Deserialize(json, ManifestJsonContext.Default.IntegrityManifest);
}

[JsonSerializable(typeof(IntegrityManifest))]
[JsonSourceGenerationOptions(WriteIndented = true)]
internal partial class ManifestJsonContext : JsonSerializerContext;
