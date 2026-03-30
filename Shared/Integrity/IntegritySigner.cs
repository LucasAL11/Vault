using System.Security.Cryptography;
using System.Text;

namespace Shared.Integrity;

/// <summary>
/// Signs and verifies integrity manifests using ECDSA P-256 (SHA-256).
/// 128-bit security level — same as AES-128 / ChaCha20.
///
/// Build-time: signs with private key (stored in CI secrets).
/// Runtime: verifies with hardcoded public key (embedded in binary).
/// </summary>
public static class IntegritySigner
{
    /// <summary>
    /// Generates a new ECDSA P-256 key pair.
    /// Returns (privateKeyBase64, publicKeyBase64).
    /// Run ONCE, store private key in CI/CD secrets, embed public key in binary.
    /// </summary>
    public static (string PrivateKeyBase64, string PublicKeyBase64) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        return (
            Convert.ToBase64String(privateKey),
            Convert.ToBase64String(publicKey)
        );
    }

    /// <summary>
    /// Signs the manifest's canonical payload with an ECDSA P-256 private key.
    /// </summary>
    public static string Sign(IntegrityManifest manifest, byte[] privateKey)
    {
        var payload = Encoding.UTF8.GetBytes(manifest.BuildCanonicalPayload());

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(privateKey, out _);

        var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA256);
        return Convert.ToBase64String(signature);
    }

    /// <summary>
    /// Verifies the manifest's signature against the canonical payload.
    /// Uses the public key hardcoded in the binary.
    /// </summary>
    public static bool Verify(IntegrityManifest manifest, byte[] publicKey)
    {
        if (string.IsNullOrEmpty(manifest.Signature))
            return false;

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(manifest.Signature);
        }
        catch (FormatException)
        {
            return false;
        }

        var payload = Encoding.UTF8.GetBytes(manifest.BuildCanonicalPayload());

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);

        return ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256);
    }
}
