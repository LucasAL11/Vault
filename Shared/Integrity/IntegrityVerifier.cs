using System.Reflection;

namespace Shared.Integrity;

/// <summary>
/// Runtime integrity verification.
/// Level 1: Self-hash — recalculates hashes and compares to manifest.
/// Level 2: Signature — verifies ECDSA P-256 signature over the manifest.
/// Level 3: Remote attestation — sends verification result to server (see IntegrityAttestationClient).
/// </summary>
public sealed class IntegrityVerifier
{
    private readonly byte[]? _trustedPublicKey;

    /// <summary>
    /// Creates a verifier with a hardcoded trusted public key for signature verification.
    /// Pass null to skip signature verification (Level 1 only).
    /// </summary>
    public IntegrityVerifier(byte[]? trustedPublicKey = null)
    {
        _trustedPublicKey = trustedPublicKey;
    }

    /// <summary>
    /// Full verification: loads manifest, checks signature, recalculates hashes.
    /// </summary>
    public IntegrityResult Verify(string? directoryPath = null)
    {
        var dir = directoryPath ?? GetAssemblyDirectory();

        // Load manifest
        var manifestPath = Path.Combine(dir, ManifestGenerator.ManifestFileName);
        if (!File.Exists(manifestPath))
        {
            return IntegrityResult.Fail("MANIFEST_MISSING",
                $"Integrity manifest not found at: {manifestPath}");
        }

        IntegrityManifest manifest;
        try
        {
            var json = File.ReadAllText(manifestPath);
            manifest = IntegrityManifest.FromJson(json)
                ?? throw new InvalidOperationException("Failed to parse manifest.");
        }
        catch (Exception ex)
        {
            return IntegrityResult.Fail("MANIFEST_CORRUPT",
                $"Cannot read integrity manifest: {ex.Message}");
        }

        // Level 2: Verify signature (if public key available)
        if (_trustedPublicKey is { Length: > 0 })
        {
            if (string.IsNullOrEmpty(manifest.Signature))
            {
                return IntegrityResult.Fail("SIGNATURE_MISSING",
                    "Manifest has no signature but signature verification is required.");
            }

            if (!IntegritySigner.Verify(manifest, _trustedPublicKey))
            {
                return IntegrityResult.Fail("SIGNATURE_INVALID",
                    "Manifest signature verification failed. Binary may have been tampered with.");
            }
        }

        // Level 1: Self-hash — recalculate and compare
        var currentHashes = IntegrityHasher.HashDirectory(dir);
        var violations = new List<IntegrityViolation>();

        // Check for modified or missing files
        foreach (var (path, expectedHash) in manifest.Files)
        {
            if (!currentHashes.TryGetValue(path, out var actualHash))
            {
                violations.Add(new IntegrityViolation(path, ViolationType.Missing, expectedHash, null));
                continue;
            }

            if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add(new IntegrityViolation(path, ViolationType.Modified, expectedHash, actualHash));
            }
        }

        // Check for added files (not in manifest)
        foreach (var (path, _) in currentHashes)
        {
            if (!manifest.Files.ContainsKey(path))
            {
                violations.Add(new IntegrityViolation(path, ViolationType.Added, null, currentHashes[path]));
            }
        }

        if (violations.Count > 0)
        {
            return IntegrityResult.Fail("HASH_MISMATCH",
                $"{violations.Count} file(s) failed integrity check.",
                violations);
        }

        return IntegrityResult.Ok(manifest);
    }

    private static string GetAssemblyDirectory()
    {
        var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
        return Path.GetDirectoryName(assembly.Location)!;
    }
}

/// <summary>
/// Result of an integrity verification.
/// </summary>
public sealed class IntegrityResult
{
    public bool IsValid { get; init; }
    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }
    public IReadOnlyList<IntegrityViolation> Violations { get; init; } = [];
    public IntegrityManifest? Manifest { get; init; }

    public static IntegrityResult Ok(IntegrityManifest manifest) => new()
    {
        IsValid = true,
        Manifest = manifest
    };

    public static IntegrityResult Fail(string code, string message, List<IntegrityViolation>? violations = null) => new()
    {
        IsValid = false,
        ErrorCode = code,
        ErrorMessage = message,
        Violations = violations ?? []
    };
}

public sealed record IntegrityViolation(
    string FilePath,
    ViolationType Type,
    string? ExpectedHash,
    string? ActualHash);

public enum ViolationType
{
    Modified,
    Missing,
    Added
}
