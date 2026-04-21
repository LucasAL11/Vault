flowchart TD
    subgraph Threats["Ameaças e Contramedidas"]
        subgraph Implemented_Threats["Contramedidas Ativas"]
            DumpDB["Ataque: Dump DB"]:::threat
            Replay["Ataque: Replay"]:::threat
            ServerBreach["Ataque: Vazamento Servidor"]:::threat
            PrivEsc["Ataque: Escalada AD"]:::threat
            DoS["Ataque: DoS / Abuso"]:::threat
            MITM["Ataque: MITM"]:::threat
            Debug["Ataque: Debugger"]:::threat
            Spoof["Ataque: HWID Spoof"]:::threat
            Downgrade["Ataque: Downgrade"]:::threat
            EncSecrets["Segredos Cifrados<br/>AES-256-GCM + AAD"]:::done
            Nonce["Nonce + Single-Use"]:::done
            HSM["KMS Key Provider"]:::done
            Claims["Validação Claims + LDAP"]:::done
            KS_Counter["Kill Switch + Denylist"]:::done
            TLS["HSTS + Security Headers<br/>(SecurityHeadersMiddleware)"]:::done
            AntiDbg2["Anti-Debug<br/>(8 técnicas — AntiDebug.cs)"]:::done
            FP2["HWID Fingerprint<br/>(CPU + BIOS + Disk + MachineGuid)"]:::done
            SignedUpd["Integridade Binária<br/>(ECDSA P-256 + SHA-256 + Attestation)"]:::done
        end
        subgraph Pending_Threats["Contramedidas Pendentes"]
            Pinning["Ataque: Cert Spoofing"]:::threat
            PinningCtrl["TLS Certificate Pinning<br/>(cliente não valida fingerprint do cert)"]:::todo
        end
    end
    classDef threat fill:#ffe6e6,stroke:#ff4d4f,color:#000
    classDef done fill:#e6ffed,stroke:#52c41a,color:#000
    classDef todo fill:#fff7e6,stroke:#faad14,color:#000