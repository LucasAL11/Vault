using Domain.vault;

namespace Application.Vault.Secrets;

public sealed record SecretAuthorizationContextDto(
    Guid VaultId,
    Status VaultStatus,
    string? VaultGroup,
    IReadOnlyCollection<string> CandidateGroups);

public sealed record SecretAuditEntryDto(
    string Action,
    string Actor,
    DateTimeOffset OccurredAtUtc,
    string? Details);

public sealed record SecretAuditDto(
    Guid VaultId,
    string SecretName,
    int Take,
    IReadOnlyCollection<SecretAuditEntryDto> Entries);

public sealed record SecretMetadataDto(
    string Name,
    int Version,
    string ContentType,
    string KeyReference,
    bool IsRevoked,
    DateTimeOffset? Expires);

public sealed record SecretVersionItemDto(
    int Version,
    string KeyId,
    string ContentType,
    bool IsRevoked,
    DateTimeOffset? Expires);

public sealed record SecretVersionsDto(
    string Name,
    int CurrentVersion,
    IReadOnlyCollection<SecretVersionItemDto> Versions);

public sealed record SecretListItemDto(
    string Name,
    string Status,
    int CurrentVersion,
    int? LatestVersion,
    string? ContentType,
    string? KeyReference,
    bool? IsRevoked,
    DateTimeOffset? Expires);

public sealed record SecretListMetadataDto(
    Guid VaultId,
    int Page,
    int PageSize,
    int TotalCount,
    int TotalPages,
    string OrderBy,
    string OrderDirection,
    string? FilterName,
    string? FilterStatus,
    IReadOnlyCollection<SecretListItemDto> Items);

public sealed record UpsertSecretResultDto(
    Guid Id,
    string Name,
    int Version,
    string KeyReference,
    DateTimeOffset? Expires);

public sealed record RequestedSecretValueDto(
    string Name,
    int Version,
    string ContentType,
    string Value,
    DateTimeOffset? Expires);

public sealed record RevokeSecretVersionResultDto(
    string Name,
    int Version,
    bool IsRevoked,
    string Reason,
    string Actor,
    bool AlreadyRevoked);
