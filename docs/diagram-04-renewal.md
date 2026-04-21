flowchart TD
    START([Timer a cada 60 min]) --> QUERY

    QUERY["Busca Secrets com versão atual expirando<br/>Status = Active, não revogado, Expires < now + 24h"] --> CHECK

    CHECK{Encontrou?}
    CHECK -->|Não| END([Ciclo concluído])
    CHECK -->|Sim| FOREACH

    FOREACH[Para cada SecretId] --> LOAD
    LOAD[Carrega Secret e versão atual com AsNoTracking] --> DECRYPT
    DECRYPT[UnprotectAsync - descriptografa valor atual] --> ENCRYPT
    ENCRYPT[ProtectAsync - re-encripta com contexto v+1] --> INSERT
    INSERT["INSERT secret_versions<br/>nova versão com expires = now + 7d"] --> UPDATE
    UPDATE["ExecuteUpdateAsync<br/>UPDATE secrets SET current_version = v+1"] --> LOG
    LOG[Log Renewed v -> v+1] --> FOREACH