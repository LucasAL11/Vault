using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Linq;
using System.Numerics;
using System.Globalization;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Application.Cryptography.Constraints;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Infrastructure.Zk.Backends;

/// <summary>
/// In-process proof backend used when no external zk service is available.
/// This is an application-local fallback and not a zero-knowledge prover.
/// </summary>
public sealed class InProcessZkBackend : IZkBackend
{
    private const int CurrentProofSchemaVersion = 1;
    private const string CurrentIrId = "sha256-preimage-r1cs";
    private const int CurrentIrMajor = 1;
    private const int CurrentIrMinor = 0;
    private const int CurrentIrPatch = 0;
    private const string CurrentIrConstraintSystem = "r1cs";
    private const string CurrentIrCurve = "bls12-381";
    private const string CurrentIrField = "fr";

    private static readonly (
        IReadOnlyList<R1csBuilder.R1csConstraint> Constraints,
        IReadOnlyDictionary<string, int> Wires) HashEqualityCircuit = Sha256EqualityR1csFactory.Build();
    private static readonly string HashEqualityCircuitFingerprintBase64 =
        ComputeConstraintHashBase64(HashEqualityCircuit.Constraints);
    private static readonly byte[] HashEqualityCircuitFingerprintBytes =
        Convert.FromBase64String(HashEqualityCircuitFingerprintBase64);
    private static readonly LocalProofIrDescriptor CurrentIrDescriptor = new(
        Id: CurrentIrId,
        Major: CurrentIrMajor,
        Minor: CurrentIrMinor,
        Patch: CurrentIrPatch,
        ConstraintSystem: CurrentIrConstraintSystem,
        Curve: CurrentIrCurve,
        Field: CurrentIrField,
        ConstraintHashBase64: HashEqualityCircuitFingerprintBase64);

    private readonly byte[] _hmacKey;
    private readonly IZkWitnessGenerator _witnessGenerator;
    private readonly IR1csSatisfiabilityValidator _r1csSatisfiabilityValidator;

    public InProcessZkBackend(
        IOptions<ZkBackendOptions> options,
        IHostEnvironment hostEnvironment,
        IZkWitnessGenerator witnessGenerator,
        IR1csSatisfiabilityValidator r1csSatisfiabilityValidator)
    {
        _witnessGenerator = witnessGenerator;
        _r1csSatisfiabilityValidator = r1csSatisfiabilityValidator;

        var key = options.Value.LocalHmacKey;
        if (string.IsNullOrWhiteSpace(key) || key.Length < 16)
        {
            throw new InvalidOperationException("ZkBackend:LocalHmacKey must have at least 16 characters.");
        }

        if (hostEnvironment.IsProduction() && !IsStrongKey(key))
        {
            throw new InvalidOperationException(
                "ZkBackend:LocalHmacKey is weak for Production. Use at least 32 bytes of entropy (base64 or strong secret).");
        }

        _hmacKey = Encoding.UTF8.GetBytes(key);
    }

    public Task<ZkProofResult> ProveAsync(PreimageRequest request, CancellationToken cancellationToken)
    {
        var witness = _witnessGenerator.Generate(request);

        byte[] secretHash = Convert.FromBase64String(witness.SecretSha256Base64);
        byte[] publicHash = Convert.FromBase64String(witness.HashPublicBase64);

        var isR1csSatisfied = IsHashEqualitySatisfiedByR1cs(secretHash, publicHash);
        var isFixedTimeEqual = CryptographicOperations.FixedTimeEquals(secretHash, publicHash);
        if (!isR1csSatisfied || !isFixedTimeEqual)
        {
            throw new InvalidOperationException("Provided hashPublic does not match SHA-256(secret).");
        }

        byte[] mac = ComputeMacWithIr(
            publicHash,
            witness.ClientId,
            witness.Nonce,
            witness.CircuitId,
            witness.Version,
            CurrentIrDescriptor);

        var payload = new LocalProofPayload(
            SchemaVersion: CurrentProofSchemaVersion,
            Ir: CurrentIrDescriptor,
            Witness: new LocalProofWitness(
                HashPublicBase64: witness.HashPublicBase64,
                ClientId: witness.ClientId,
                Nonce: witness.Nonce,
                CircuitId: witness.CircuitId,
                Version: witness.Version),
            MacBase64: Convert.ToBase64String(mac));

        byte[] proofBytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        return Task.FromResult(new ZkProofResult(Proof: proofBytes, PublicInputs: publicHash));
    }

    public Task<bool> VerifyAsync(VerificationRequest request, CancellationToken cancellationToken)
    {
        var hashParsed = TryNormalizeHashInput(request.HashPublic, out var expectedHash);
        var proofParsed = TryParseBase64AnyLength(request.Proof, out var proofBytes);
        var payloadParsed = TryDeserializePayload(proofBytes, out var payload);

        var witness = payload?.Witness;
        var hasWitness = witness is not null;
        var schemaMatch = payload?.SchemaVersion == CurrentProofSchemaVersion;
        var hasIrDescriptor = payload?.Ir is not null;
        var irDescriptor = payload?.Ir;
        var irSupported = !hasIrDescriptor || IsSupportedIr(irDescriptor);
        var normalizedIrForMac = NormalizeIrForMac(irDescriptor);

        var clientId = witness?.ClientId ?? string.Empty;
        var nonce = witness?.Nonce ?? string.Empty;
        var circuitId = witness?.CircuitId ?? string.Empty;
        var circuitVersion = witness?.Version ?? 0;
        var hasValidCircuit = !string.IsNullOrWhiteSpace(circuitId) && circuitVersion > 0;
        var normalizedCircuitId = hasValidCircuit ? circuitId : "invalid-circuit";
        var normalizedCircuitVersion = hasValidCircuit ? circuitVersion : 1;

        var hashFromProofParsed = TryParseBase64(witness?.HashPublicBase64 ?? string.Empty, out var hashFromProof);
        var macFromProofParsed = TryParseBase64(payload?.MacBase64 ?? string.Empty, out var macFromProof);

        Span<byte> expectedHashForMac = stackalloc byte[32];
        expectedHashForMac.Clear();
        if (hashParsed && expectedHash.Length > 0)
        {
            expectedHash.AsSpan(0, Math.Min(expectedHash.Length, expectedHashForMac.Length)).CopyTo(expectedHashForMac);
        }

        byte[] expectedMacWithIr = ComputeMacWithIr(
            expectedHashForMac.ToArray(),
            clientId,
            nonce,
            normalizedCircuitId,
            normalizedCircuitVersion,
            normalizedIrForMac);
        byte[] expectedMacLegacy = ComputeMacLegacy(
            expectedHashForMac.ToArray(),
            clientId,
            nonce,
            normalizedCircuitId,
            normalizedCircuitVersion);

        var isClientMatch = string.Equals(clientId, request.ClientId, StringComparison.Ordinal);
        var isNonceMatch = string.Equals(nonce, request.Nonce, StringComparison.Ordinal);
        var isHashMatch = hashFromProofParsed &&
                          hashParsed &&
                          FixedTimeEqualsWithExpectedLength(hashFromProof, expectedHash, 32);
        var isHashR1csSatisfied = hashFromProofParsed &&
                                  hashParsed &&
                                  IsHashEqualitySatisfiedByR1cs(hashFromProof, expectedHash);
        var isMacMatchWithIr = macFromProofParsed &&
                               FixedTimeEqualsWithExpectedLength(macFromProof, expectedMacWithIr, 32);
        var isMacMatchLegacy = macFromProofParsed &&
                               FixedTimeEqualsWithExpectedLength(macFromProof, expectedMacLegacy, 32);
        var isMacMatch = hasIrDescriptor
            ? isMacMatchWithIr
            : isMacMatchLegacy;

        var isValid = proofParsed &
                      payloadParsed &
                      hasWitness &
                      schemaMatch &
                      irSupported &
                      hasValidCircuit &
                      isClientMatch &
                      isNonceMatch &
                      isHashMatch &
                      isHashR1csSatisfied &
                      isMacMatch;

        return Task.FromResult(isValid);
    }

    private static LocalProofIrDescriptor NormalizeIrForMac(LocalProofIrDescriptor? ir)
    {
        if (ir is null)
        {
            return new LocalProofIrDescriptor(
                Id: "legacy-ir-none",
                Major: 0,
                Minor: 0,
                Patch: 0,
                ConstraintSystem: "legacy",
                Curve: "legacy",
                Field: "legacy",
                ConstraintHashBase64: Convert.ToBase64String(new byte[32]));
        }

        return new LocalProofIrDescriptor(
            Id: ir.Id ?? string.Empty,
            Major: ir.Major,
            Minor: ir.Minor,
            Patch: ir.Patch,
            ConstraintSystem: ir.ConstraintSystem ?? string.Empty,
            Curve: ir.Curve ?? string.Empty,
            Field: ir.Field ?? string.Empty,
            ConstraintHashBase64: ir.ConstraintHashBase64 ?? string.Empty);
    }

    private static bool IsSupportedIr(LocalProofIrDescriptor? ir)
    {
        if (ir is null)
        {
            return false;
        }

        if (!string.Equals(ir.Id, CurrentIrId, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.Equals(ir.ConstraintSystem, CurrentIrConstraintSystem, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.Equals(ir.Curve, CurrentIrCurve, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.Equals(ir.Field, CurrentIrField, StringComparison.Ordinal))
        {
            return false;
        }

        if (ir.Major != CurrentIrMajor)
        {
            return false;
        }

        if (ir.Minor > CurrentIrMinor)
        {
            return false;
        }

        if (!TryParseBase64(ir.ConstraintHashBase64 ?? string.Empty, out var irHashBytes))
        {
            return false;
        }

        return FixedTimeEqualsWithExpectedLength(irHashBytes, HashEqualityCircuitFingerprintBytes, 32);
    }

    private bool IsHashEqualitySatisfiedByR1cs(byte[] leftHash, byte[] rightHash)
    {
        if (leftHash.Length != Sha256EqualityR1csFactory.HashSizeBytes ||
            rightHash.Length != Sha256EqualityR1csFactory.HashSizeBytes)
        {
            return false;
        }

        var witness = new Dictionary<int, BigInteger>
        {
            [R1csBuilder.ConstantWireId] = BigInteger.One
        };

        for (var i = 0; i < Sha256EqualityR1csFactory.HashSizeBytes; i++)
        {
            witness[HashEqualityCircuit.Wires[$"lhs_{i}"]] = leftHash[i];
            witness[HashEqualityCircuit.Wires[$"rhs_{i}"]] = rightHash[i];
        }

        var result = _r1csSatisfiabilityValidator.Validate(
            HashEqualityCircuit.Constraints,
            witness,
            R1csBuilder.Bls12_381ScalarFieldPrime);

        return result.IsSatisfied;
    }

    private static bool FixedTimeEqualsWithExpectedLength(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, int expectedLength)
    {
        Span<byte> leftBuffer = stackalloc byte[expectedLength];
        Span<byte> rightBuffer = stackalloc byte[expectedLength];
        leftBuffer.Clear();
        rightBuffer.Clear();

        var leftCopy = Math.Min(left.Length, expectedLength);
        var rightCopy = Math.Min(right.Length, expectedLength);
        left[..leftCopy].CopyTo(leftBuffer);
        right[..rightCopy].CopyTo(rightBuffer);

        var bytesEqual = CryptographicOperations.FixedTimeEquals(leftBuffer, rightBuffer);
        var lengthsEqual = left.Length == expectedLength && right.Length == expectedLength;
        return bytesEqual & lengthsEqual;
    }

    private static bool TryParseBase64AnyLength(string input, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(input);
            return bytes.Length > 0;
        }
        catch
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static bool TryDeserializePayload(ReadOnlySpan<byte> payloadBytes, out LocalProofPayload? payload)
    {
        try
        {
            payload = JsonSerializer.Deserialize<LocalProofPayload>(payloadBytes);
            return payload is not null;
        }
        catch (JsonException)
        {
            payload = null;
            return false;
        }
    }

    private static bool TryNormalizeHashInput(string hashPublic, out byte[] hashBytes)
    {
        try
        {
            hashBytes = NormalizeHashInput(hashPublic);
            return true;
        }
        catch
        {
            hashBytes = Array.Empty<byte>();
            return false;
        }
    }

    private byte[] ComputeMacLegacy(
        byte[] hashPublicBytes,
        string clientId,
        string nonce,
        string circuitId,
        int version)
    {
        var metadata = $"{clientId}|{nonce}|{circuitId}|{version}";
        return ComputeMacCore(hashPublicBytes, metadata);
    }

    private byte[] ComputeMacWithIr(
        byte[] hashPublicBytes,
        string clientId,
        string nonce,
        string circuitId,
        int version,
        LocalProofIrDescriptor ir)
    {
        var metadata =
            $"{clientId}|{nonce}|{circuitId}|{version}|ir:{ir.Id}|{ir.Major}.{ir.Minor}.{ir.Patch}|{ir.ConstraintSystem}|{ir.Curve}|{ir.Field}|{ir.ConstraintHashBase64}";
        return ComputeMacCore(hashPublicBytes, metadata);
    }

    private byte[] ComputeMacCore(byte[] hashPublicBytes, string metadata)
    {
        using var hmac = new HMACSHA256(_hmacKey);
        var meta = Encoding.UTF8.GetBytes(metadata);
        var payload = new byte[hashPublicBytes.Length + meta.Length];
        Buffer.BlockCopy(hashPublicBytes, 0, payload, 0, hashPublicBytes.Length);
        Buffer.BlockCopy(meta, 0, payload, hashPublicBytes.Length, meta.Length);
        return hmac.ComputeHash(payload);
    }

    private static string ComputeConstraintHashBase64(IReadOnlyList<R1csBuilder.R1csConstraint> constraints)
    {
        var canonical = new StringBuilder(capacity: 4096);
        for (var i = 0; i < constraints.Count; i++)
        {
            canonical.Append("i=").Append(i.ToString(CultureInfo.InvariantCulture)).Append('|');
            AppendVector(canonical, "A", constraints[i].A);
            AppendVector(canonical, "B", constraints[i].B);
            AppendVector(canonical, "C", constraints[i].C);
            canonical.Append(';');
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()));
        return Convert.ToBase64String(hash);
    }

    private static void AppendVector(StringBuilder builder, string name, R1csBuilder.SparseVec vector)
    {
        builder.Append(name).Append(':');
        var orderedTerms = vector.Terms.OrderBy(t => t.Key);
        foreach (var (wireIndex, coeff) in orderedTerms)
        {
            builder.Append(wireIndex.ToString(CultureInfo.InvariantCulture))
                .Append('=')
                .Append(coeff.ToString(CultureInfo.InvariantCulture))
                .Append(',');
        }

        builder.Append('|');
    }

    private static byte[] NormalizeHashInput(string hashPublic)
    {
        if (LooksLikeHex(hashPublic) && TryParseHex(hashPublic, out var hexBytes))
        {
            return hexBytes;
        }

        if (TryParseBase64(hashPublic, out var bytes))
        {
            return bytes;
        }

        if (TryParseHex(hashPublic, out bytes))
        {
            return bytes;
        }

        throw new InvalidOperationException("hashPublic must be base64 or hex-encoded SHA-256.");
    }

    private static bool TryParseBase64(string input, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(input);
            return bytes.Length == 32;
        }
        catch
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static bool TryParseHex(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input) || input.Length % 2 != 0)
        {
            return false;
        }

        var buffer = new byte[input.Length / 2];
        for (int i = 0; i < buffer.Length; i++)
        {
            int hi = HexValue(input[2 * i]);
            int lo = HexValue(input[2 * i + 1]);
            if (hi < 0 || lo < 0)
            {
                return false;
            }

            buffer[i] = (byte)((hi << 4) | lo);
        }

        bytes = buffer;
        return bytes.Length > 0;
    }

    private static int HexValue(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static bool LooksLikeHex(string input)
    {
        if (string.IsNullOrWhiteSpace(input) || input.Length % 2 != 0)
        {
            return false;
        }

        for (int i = 0; i < input.Length; i++)
        {
            if (HexValue(input[i]) < 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsStrongKey(string key)
    {
        const string defaultDevKey = "dev-local-zk-key-change-me";
        if (string.Equals(key, defaultDevKey, StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var decoded = Convert.FromBase64String(key);
            if (decoded.Length >= 32)
            {
                return true;
            }
        }
        catch
        {
            // not base64, fallback to plain-text heuristics
        }

        if (Encoding.UTF8.GetByteCount(key) < 32)
        {
            return false;
        }

        int classes = 0;
        if (key.Any(char.IsLower)) classes++;
        if (key.Any(char.IsUpper)) classes++;
        if (key.Any(char.IsDigit)) classes++;
        if (key.Any(c => !char.IsLetterOrDigit(c))) classes++;
        return classes >= 3;
    }

    private sealed record LocalProofPayload(
        int SchemaVersion,
        LocalProofIrDescriptor? Ir,
        LocalProofWitness Witness,
        string MacBase64);

    private sealed record LocalProofIrDescriptor(
        string? Id,
        int Major,
        int Minor,
        int Patch,
        string? ConstraintSystem,
        string? Curve,
        string? Field,
        string? ConstraintHashBase64);

    private sealed record LocalProofWitness(
        string HashPublicBase64,
        string ClientId,
        string Nonce,
        string CircuitId,
        int Version);
}
