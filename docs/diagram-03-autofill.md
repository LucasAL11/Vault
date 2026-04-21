sequenceDiagram
    actor User
    participant PG as Popup_Content
    participant SW as ServiceWorker
    participant CH as POST_auth_challenge
    participant REQ as POST_secrets_request
    participant PROT as ChaCha20SecretProtector

    User->>PG: Clica no segredo
    PG->>SW: autofillSecret

    SW->>CH: clientId + subject DOMAIN_user + audience request
    CH-->>SW: nonce + issuedAtUtc + expiresAtUtc

    SW->>SW: payload string montado
    SW->>SW: proof HMAC SHA256 base64url

    SW->>REQ: envia contractVersion + clientId + nonce + proof

    REQ->>REQ: valida vault Active
    REQ->>REQ: valida grupo AD
    REQ->>REQ: valida assinatura tempo constante
    REQ->>REQ: valida janela nonce
    REQ->>REQ: consome nonce anti replay

    REQ->>PROT: UnprotectAsync
    PROT-->>REQ: plaintext

    REQ-->>SW: value + version + expires

    SW->>PG: sendMessage fillFields
    PG->>PG: fillField password
    PG->>PG: lockPasswordField