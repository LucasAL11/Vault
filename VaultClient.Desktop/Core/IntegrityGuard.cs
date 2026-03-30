using System.Net.Http;
using System.Windows;
using Shared.Integrity;

namespace VaultClient.Desktop.Core;

/// <summary>
/// Startup integrity guard for the Desktop client.
/// Runs all 3 levels of binary integrity verification:
///   Level 1: Self-hash (compare file hashes to manifest)
///   Level 2: Signature (verify ECDSA P-256 signature)
///   Level 3: Remote attestation (report to server)
///
/// If verification fails, the application refuses to start.
/// </summary>
public static class IntegrityGuard
{
    // ========================================================
    // HARDCODED PUBLIC KEY — generated once, embedded forever.
    // The private key lives ONLY in CI/CD secrets.
    // An attacker who modifies the binary cannot forge a valid
    // manifest because they don't have the private key.
    //
    // To generate a new key pair, run:
    //   var (priv, pub) = IntegritySigner.GenerateKeyPair();
    //   Console.WriteLine($"PRIVATE (CI only): {priv}");
    //   Console.WriteLine($"PUBLIC (embed):    {pub}");
    //
    // Replace the string below with YOUR public key.
    // ========================================================
    private const string TrustedPublicKeyBase64 =
        ""; // Empty = skip signature verification (dev mode)

    /// <summary>
    /// Runs integrity verification. Call this BEFORE any business logic.
    /// Returns the result for attestation; throws/exits on failure.
    /// </summary>
    public static IntegrityResult VerifyOrDie(bool exitOnFailure = true)
    {
        byte[]? publicKey = null;
        if (!string.IsNullOrEmpty(TrustedPublicKeyBase64))
        {
            publicKey = Convert.FromBase64String(TrustedPublicKeyBase64);
        }

        var verifier = new IntegrityVerifier(publicKey);
        var result = verifier.Verify();

        if (!result.IsValid && exitOnFailure)
        {
            var message = FormatFailureMessage(result);

            MessageBox.Show(
                message,
                "Falha de Integridade",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            Environment.Exit(0xDEAD);
        }

        return result;
    }

    /// <summary>
    /// Level 3: Reports integrity status to the server.
    /// Call after VerifyOrDie() — even on success, so the server
    /// has a record of all client attestations.
    /// </summary>
    public static async Task AttestToServerAsync(
        IntegrityResult result,
        string serverUrl,
        string clientId,
        string hwid)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            var client = new IntegrityAttestationClient(http, serverUrl);
            var response = await client.AttestAsync(result, clientId, hwid);

            if (!response.Allowed)
            {
                // Server says this binary is not trusted
                MessageBox.Show(
                    $"O servidor rejeitou este cliente.\n\nMotivo: {response.Reason}\nAcao: {response.Action}",
                    "Acesso Negado pelo Servidor",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);

                if (response.Action is "block" or "kill")
                {
                    Environment.Exit(0xDEAD);
                }
            }
        }
        catch (Exception ex)
        {
            // Network failure during attestation — log but don't block
            // (fail-open for attestation, fail-closed for local verification)
            System.Diagnostics.Debug.WriteLine($"Attestation failed: {ex.Message}");
        }
    }

    private static string FormatFailureMessage(IntegrityResult result)
    {
        var lines = new List<string>
        {
            "INTEGRIDADE DO BINARIO COMPROMETIDA",
            "",
            $"Codigo: {result.ErrorCode}",
            $"Detalhe: {result.ErrorMessage}",
            ""
        };

        if (result.Violations.Count > 0)
        {
            lines.Add($"Arquivos comprometidos ({result.Violations.Count}):");
            foreach (var v in result.Violations.Take(10))
            {
                lines.Add(v.Type switch
                {
                    ViolationType.Modified => $"  MODIFICADO: {v.FilePath}",
                    ViolationType.Missing => $"  REMOVIDO:   {v.FilePath}",
                    ViolationType.Added => $"  ADICIONADO: {v.FilePath}",
                    _ => $"  {v.Type}: {v.FilePath}"
                });
            }

            if (result.Violations.Count > 10)
                lines.Add($"  ... e mais {result.Violations.Count - 10} arquivo(s).");
        }

        lines.Add("");
        lines.Add("O aplicativo sera encerrado por seguranca.");
        lines.Add("Reinstale o aplicativo a partir de uma fonte confiavel.");

        return string.Join("\n", lines);
    }
}
