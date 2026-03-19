# Secret Cache Policy

## Objective
- Never keep secret plaintext in memory cache, distributed cache, or response cache.

## Current Strategy
- Plaintext is only handled in-flight during request execution and immediately encrypted with AES-GCM before persistence.
- Secret endpoints return HTTP anti-cache headers:
  - `Cache-Control: no-store, no-cache, max-age=0`
  - `Pragma: no-cache`
  - `Expires: 0`
- API does not expose plaintext via `GET /vaults/{vaultId}/secrets/{name}` (metadata only).

## If Cache Is Needed
- Allow cache only for non-sensitive metadata (example: vault policy/group lookup).
- Use short TTL (15-60 seconds), scoped by tenant/vault, with explicit invalidation on updates.
- Do not cache decrypted values or raw ciphertext+nonce bundles outside DB context.

## Validation Checklist
- Confirm no `IMemoryCache`/`IDistributedCache` usage for secret value paths.
- Confirm response headers include `no-store` on secret endpoints.
- Confirm error responses and logs never include secret payload.
