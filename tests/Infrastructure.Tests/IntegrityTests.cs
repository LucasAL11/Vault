using System.Text;
using Shared.Integrity;
using Xunit;

namespace Infrastructure.Tests;

public class IntegrityTests : IDisposable
{
    private readonly string _tempDir;

    public IntegrityTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"vault-integrity-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private void CreateFile(string name, string content)
    {
        File.WriteAllText(Path.Combine(_tempDir, name), content);
    }

    // --- Hasher tests ---

    [Fact]
    public void HashFile_ShouldReturnConsistentHash()
    {
        CreateFile("test.dll", "hello world");
        var hash1 = IntegrityHasher.HashFile(Path.Combine(_tempDir, "test.dll"));
        var hash2 = IntegrityHasher.HashFile(Path.Combine(_tempDir, "test.dll"));
        Assert.Equal(hash1, hash2);
        Assert.Equal(64, hash1.Length); // SHA-256 hex = 64 chars
    }

    [Fact]
    public void HashFile_DifferentContent_ShouldReturnDifferentHash()
    {
        CreateFile("a.dll", "content-a");
        CreateFile("b.dll", "content-b");
        var hashA = IntegrityHasher.HashFile(Path.Combine(_tempDir, "a.dll"));
        var hashB = IntegrityHasher.HashFile(Path.Combine(_tempDir, "b.dll"));
        Assert.NotEqual(hashA, hashB);
    }

    [Fact]
    public void HashDirectory_ShouldOnlyTrackKnownExtensions()
    {
        CreateFile("app.dll", "dll content");
        CreateFile("app.exe", "exe content");
        CreateFile("readme.txt", "ignored");
        CreateFile("photo.png", "ignored");

        var hashes = IntegrityHasher.HashDirectory(_tempDir);

        Assert.Contains("app.dll", hashes.Keys);
        Assert.Contains("app.exe", hashes.Keys);
        Assert.DoesNotContain("readme.txt", hashes.Keys);
        Assert.DoesNotContain("photo.png", hashes.Keys);
    }

    // --- Signer tests ---

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeys()
    {
        var (priv, pub) = IntegritySigner.GenerateKeyPair();
        Assert.NotEmpty(priv);
        Assert.NotEmpty(pub);

        var privBytes = Convert.FromBase64String(priv);
        var pubBytes = Convert.FromBase64String(pub);
        Assert.True(privBytes.Length > 0);
        Assert.True(pubBytes.Length > 0);
    }

    [Fact]
    public void SignAndVerify_ShouldSucceed()
    {
        var (priv, pub) = IntegritySigner.GenerateKeyPair();
        var privBytes = Convert.FromBase64String(priv);
        var pubBytes = Convert.FromBase64String(pub);

        var manifest = new IntegrityManifest
        {
            AssemblyName = "TestApp",
            AssemblyVersion = "1.0.0",
            Files = new Dictionary<string, string>
            {
                ["app.dll"] = "abc123",
                ["lib.dll"] = "def456"
            }
        };

        manifest.Signature = IntegritySigner.Sign(manifest, privBytes);
        Assert.NotEmpty(manifest.Signature);

        var isValid = IntegritySigner.Verify(manifest, pubBytes);
        Assert.True(isValid);
    }

    [Fact]
    public void Verify_TamperedManifest_ShouldFail()
    {
        var (priv, pub) = IntegritySigner.GenerateKeyPair();
        var privBytes = Convert.FromBase64String(priv);
        var pubBytes = Convert.FromBase64String(pub);

        var manifest = new IntegrityManifest
        {
            AssemblyName = "TestApp",
            AssemblyVersion = "1.0.0",
            Files = new Dictionary<string, string>
            {
                ["app.dll"] = "abc123"
            }
        };

        manifest.Signature = IntegritySigner.Sign(manifest, privBytes);

        // Tamper with the manifest after signing
        manifest.Files["app.dll"] = "tampered_hash";

        var isValid = IntegritySigner.Verify(manifest, pubBytes);
        Assert.False(isValid);
    }

    [Fact]
    public void Verify_WrongKey_ShouldFail()
    {
        var (priv1, _) = IntegritySigner.GenerateKeyPair();
        var (_, pub2) = IntegritySigner.GenerateKeyPair();
        var privBytes = Convert.FromBase64String(priv1);
        var pubBytes = Convert.FromBase64String(pub2);

        var manifest = new IntegrityManifest
        {
            AssemblyName = "TestApp",
            AssemblyVersion = "1.0.0",
            Files = new Dictionary<string, string> { ["x.dll"] = "abc" }
        };

        manifest.Signature = IntegritySigner.Sign(manifest, privBytes);

        // Verify with DIFFERENT public key
        var isValid = IntegritySigner.Verify(manifest, pubBytes);
        Assert.False(isValid);
    }

    // --- Manifest Generator tests ---

    [Fact]
    public void ManifestGenerator_ShouldHashAllTrackedFiles()
    {
        CreateFile("app.dll", "main binary");
        CreateFile("lib.dll", "library");
        CreateFile("config.json", "{}");

        var manifest = ManifestGenerator.Generate(_tempDir, "TestApp", "1.0.0");

        Assert.Equal("TestApp", manifest.AssemblyName);
        Assert.Equal("1.0.0", manifest.AssemblyVersion);
        Assert.Contains("app.dll", manifest.Files.Keys);
        Assert.Contains("lib.dll", manifest.Files.Keys);
        Assert.Contains("config.json", manifest.Files.Keys);
    }

    [Fact]
    public void ManifestGenerator_WithSigningKey_ShouldProduceSignedManifest()
    {
        CreateFile("app.dll", "binary content");

        var (priv, pub) = IntegritySigner.GenerateKeyPair();
        var privBytes = Convert.FromBase64String(priv);
        var pubBytes = Convert.FromBase64String(pub);

        var manifest = ManifestGenerator.Generate(_tempDir, "TestApp", "1.0.0", privBytes);

        Assert.NotEmpty(manifest.Signature);
        Assert.True(IntegritySigner.Verify(manifest, pubBytes));
    }

    // --- Verifier tests (full pipeline) ---

    [Fact]
    public void Verifier_NoManifest_ShouldFail()
    {
        var verifier = new IntegrityVerifier();
        var result = verifier.Verify(_tempDir);

        Assert.False(result.IsValid);
        Assert.Equal("MANIFEST_MISSING", result.ErrorCode);
    }

    [Fact]
    public void Verifier_ValidManifest_ShouldPass()
    {
        CreateFile("app.dll", "binary content");
        CreateFile("lib.dll", "library content");

        // Generate and save manifest
        ManifestGenerator.GenerateAndSave(_tempDir, "TestApp", "1.0.0");

        var verifier = new IntegrityVerifier();
        var result = verifier.Verify(_tempDir);

        Assert.True(result.IsValid);
        Assert.NotNull(result.Manifest);
        Assert.Empty(result.Violations);
    }

    [Fact]
    public void Verifier_ModifiedFile_ShouldDetect()
    {
        CreateFile("app.dll", "original content");

        ManifestGenerator.GenerateAndSave(_tempDir, "TestApp", "1.0.0");

        // Modify file AFTER manifest was created
        CreateFile("app.dll", "TAMPERED content");

        var verifier = new IntegrityVerifier();
        var result = verifier.Verify(_tempDir);

        Assert.False(result.IsValid);
        Assert.Equal("HASH_MISMATCH", result.ErrorCode);
        Assert.Contains(result.Violations, v =>
            v.FilePath == "app.dll" && v.Type == ViolationType.Modified);
    }

    [Fact]
    public void Verifier_DeletedFile_ShouldDetect()
    {
        CreateFile("app.dll", "binary");
        CreateFile("lib.dll", "library");

        ManifestGenerator.GenerateAndSave(_tempDir, "TestApp", "1.0.0");

        // Delete a file
        File.Delete(Path.Combine(_tempDir, "lib.dll"));

        var verifier = new IntegrityVerifier();
        var result = verifier.Verify(_tempDir);

        Assert.False(result.IsValid);
        Assert.Contains(result.Violations, v =>
            v.FilePath == "lib.dll" && v.Type == ViolationType.Missing);
    }

    [Fact]
    public void Verifier_AddedFile_ShouldDetect()
    {
        CreateFile("app.dll", "binary");

        ManifestGenerator.GenerateAndSave(_tempDir, "TestApp", "1.0.0");

        // Add a new file (e.g., injected DLL)
        CreateFile("malware.dll", "evil payload");

        var verifier = new IntegrityVerifier();
        var result = verifier.Verify(_tempDir);

        Assert.False(result.IsValid);
        Assert.Contains(result.Violations, v =>
            v.FilePath == "malware.dll" && v.Type == ViolationType.Added);
    }

    [Fact]
    public void Verifier_SignedManifest_ValidSignature_ShouldPass()
    {
        CreateFile("app.dll", "binary");

        var (priv, pub) = IntegritySigner.GenerateKeyPair();
        var privBytes = Convert.FromBase64String(priv);
        var pubBytes = Convert.FromBase64String(pub);

        ManifestGenerator.GenerateAndSave(_tempDir, "TestApp", "1.0.0", privBytes);

        var verifier = new IntegrityVerifier(pubBytes);
        var result = verifier.Verify(_tempDir);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verifier_SignedManifest_TamperedSignature_ShouldFail()
    {
        CreateFile("app.dll", "binary");

        var (priv, pub) = IntegritySigner.GenerateKeyPair();
        var privBytes = Convert.FromBase64String(priv);
        var pubBytes = Convert.FromBase64String(pub);

        var manifest = ManifestGenerator.Generate(_tempDir, "TestApp", "1.0.0", privBytes);

        // Tamper with a hash in the manifest
        manifest.Files["app.dll"] = "0000000000000000000000000000000000000000000000000000000000000000";
        File.WriteAllText(Path.Combine(_tempDir, "integrity-manifest.json"), manifest.ToJson());

        var verifier = new IntegrityVerifier(pubBytes);
        var result = verifier.Verify(_tempDir);

        Assert.False(result.IsValid);
        Assert.Equal("SIGNATURE_INVALID", result.ErrorCode);
    }

    [Fact]
    public void Verifier_RequiresSignature_ButManifestUnsigned_ShouldFail()
    {
        CreateFile("app.dll", "binary");

        // Generate WITHOUT signing
        ManifestGenerator.GenerateAndSave(_tempDir, "TestApp", "1.0.0");

        // But verify WITH a public key (requires signature)
        var (_, pub) = IntegritySigner.GenerateKeyPair();
        var pubBytes = Convert.FromBase64String(pub);

        var verifier = new IntegrityVerifier(pubBytes);
        var result = verifier.Verify(_tempDir);

        Assert.False(result.IsValid);
        Assert.Equal("SIGNATURE_MISSING", result.ErrorCode);
    }

    // --- Canonical payload tests ---

    [Fact]
    public void CanonicalPayload_ShouldBeDeterministic()
    {
        var manifest = new IntegrityManifest
        {
            Files = new Dictionary<string, string>
            {
                ["z.dll"] = "hash_z",
                ["a.dll"] = "hash_a",
                ["m.dll"] = "hash_m"
            }
        };

        var payload = manifest.BuildCanonicalPayload();

        // Should be sorted alphabetically
        Assert.Equal("a.dll=hash_a\nm.dll=hash_m\nz.dll=hash_z", payload);
    }

    // --- Serialization tests ---

    [Fact]
    public void Manifest_SerializeDeserialize_ShouldRoundTrip()
    {
        var manifest = new IntegrityManifest
        {
            Version = 1,
            BuildTimestamp = DateTimeOffset.UtcNow,
            AssemblyName = "TestApp",
            AssemblyVersion = "1.0.0",
            Files = new Dictionary<string, string>
            {
                ["app.dll"] = "abc123",
                ["lib.dll"] = "def456"
            },
            Signature = "test-sig"
        };

        var json = manifest.ToJson();
        var deserialized = IntegrityManifest.FromJson(json);

        Assert.NotNull(deserialized);
        Assert.Equal(manifest.AssemblyName, deserialized!.AssemblyName);
        Assert.Equal(manifest.Files.Count, deserialized.Files.Count);
        Assert.Equal(manifest.Signature, deserialized.Signature);
    }
}
