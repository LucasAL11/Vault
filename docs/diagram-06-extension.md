flowchart LR
    subgraph POPUP["popup.js"]
        LOGIN[Login Form]
        VAULTS[Vault List]
        SECRETS[Secret List]
    end

    subgraph SW["service-worker.js"]
        MSG{handleMessage}
        AUTH[authenticate]
        LIST_V[listVaults]
        LIST_S[listSecrets]
        AUTOFILL[requestSecretValue + HMAC proof]
        RULE[createAutofillRule / matchAutofillRules]
    end

    subgraph CONTENT["autofill.js (content script)"]
        BADGE[Vault Badges]
        MENU[Inline Menu]
        FILL[fillField]
        LOCK[lockPasswordField]
        AUTO[tryAutoMatch / autofill bar]
    end

    subgraph API["API"]
        API_AUTH["POST /users"]
        API_VAULT["GET /vaults"]
        API_SEC["GET /vaults/:id/secrets"]
        API_REQ["POST /secrets/:name/request"]
        API_MATCH["GET /autofill-rules/match"]
    end

    LOGIN -->|send login| MSG
    VAULTS -->|send listVaults| MSG
    SECRETS -->|send listSecrets| MSG
    SECRETS -->|send autofillSecret| MSG

    MSG --> AUTH --> API_AUTH
    MSG --> LIST_V --> API_VAULT
    MSG --> LIST_S --> API_SEC
    MSG --> AUTOFILL --> API_REQ
    MSG --> RULE --> API_MATCH

    AUTOFILL -->|sendMessage fillFields| FILL
    FILL --> LOCK

    AUTO -->|matchRules on load| API_MATCH
    BADGE -->|click| MENU
    MENU -->|select secret| AUTOFILL