using System.Security.Cryptography;

namespace Shared.Integrity;

/// <summary>
/// Computes SHA-256 hashes for files in a directory.
/// Used both at build-time (manifest generation) and runtime (verification).
/// </summary>
public static class IntegrityHasher
{
    private static readonly string[] TrackedExtensions =
    [
        ".dll", ".exe", ".json", ".xml", ".pdb"
    ];

    /// <summary>
    /// Hashes all tracked files in the given directory.
    /// Returns dictionary of relative path → hex SHA-256.
    /// </summary>
    public static Dictionary<string, string> HashDirectory(string directoryPath, string[]? extensions = null)
    {
        var exts = extensions ?? TrackedExtensions;
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var basePath = Path.GetFullPath(directoryPath);

        foreach (var file in Directory.EnumerateFiles(basePath, "*.*", SearchOption.AllDirectories))
        {
            var ext = Path.GetExtension(file);
            if (!exts.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                continue;

            // Skip the manifest itself
            var fileName = Path.GetFileName(file);
            if (fileName.Equals("integrity-manifest.json", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("integrity-manifest.json.sig", StringComparison.OrdinalIgnoreCase))
                continue;

            var relativePath = Path.GetRelativePath(basePath, file).Replace('\\', '/');
            hashes[relativePath] = HashFile(file);
        }

        return hashes;
    }

    /// <summary>
    /// Hashes a single file, returning hex-encoded SHA-256.
    /// </summary>
    public static string HashFile(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexStringLower(hash);
    }

    /// <summary>
    /// Hashes raw bytes, returning hex-encoded SHA-256.
    /// </summary>
    public static string HashBytes(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexStringLower(hash);
    }
}
