using System.Reflection;

namespace Shared.Integrity;

/// <summary>
/// Build-time utility: scans an output directory, hashes all tracked files,
/// signs the manifest, and writes it to disk.
///
/// Usage in CI/CD:
///   dotnet run --project Tools/IntegrityTool -- sign \
///       --dir publish/ \
///       --key $SIGNING_PRIVATE_KEY_BASE64 \
///       --output publish/integrity-manifest.json
/// </summary>
public static class ManifestGenerator
{
    public const string ManifestFileName = "integrity-manifest.json";

    /// <summary>
    /// Generates and signs a manifest for all tracked files in the directory.
    /// </summary>
    public static IntegrityManifest Generate(
        string directoryPath,
        string assemblyName,
        string assemblyVersion,
        byte[]? privateKey = null)
    {
        var hashes = IntegrityHasher.HashDirectory(directoryPath);

        var manifest = new IntegrityManifest
        {
            Version = 1,
            BuildTimestamp = DateTimeOffset.UtcNow,
            AssemblyName = assemblyName,
            AssemblyVersion = assemblyVersion,
            Files = hashes
        };

        if (privateKey is { Length: > 0 })
        {
            manifest.Signature = IntegritySigner.Sign(manifest, privateKey);
        }

        return manifest;
    }

    /// <summary>
    /// Generates, signs, and writes the manifest to disk.
    /// </summary>
    public static string GenerateAndSave(
        string directoryPath,
        string assemblyName,
        string assemblyVersion,
        byte[]? privateKey = null)
    {
        var manifest = Generate(directoryPath, assemblyName, assemblyVersion, privateKey);
        var json = manifest.ToJson();
        var outputPath = Path.Combine(directoryPath, ManifestFileName);
        File.WriteAllText(outputPath, json);
        return outputPath;
    }

    /// <summary>
    /// Generates a manifest from the currently running assembly's directory.
    /// Useful for creating the initial manifest during development.
    /// </summary>
    public static IntegrityManifest GenerateFromCurrentAssembly(byte[]? privateKey = null)
    {
        var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
        var dir = Path.GetDirectoryName(assembly.Location)!;
        var name = assembly.GetName();

        return Generate(
            dir,
            name.Name ?? "Unknown",
            name.Version?.ToString() ?? "0.0.0",
            privateKey);
    }
}
