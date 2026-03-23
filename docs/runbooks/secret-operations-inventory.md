# Inventario de Operacoes com Segredo

> STATUS: PARCIALMENTE LEGADO.
> A secao de operacoes ZK/Cryptography e historica; rotas ZK foram removidas do runtime da API no caminho MVP sem ZK.

## Escopo

Inventario dos fluxos que manipulam segredo ou derivados de segredo nas categorias:

- `hash`
- `MAC`
- `scalar`
- `nonce`
- `proof bytes`

Legenda de material sensivel:

- `segredo bruto`: valor em claro (senha/chave/secret).
- `derivado`: hash/MAC/proof derivados de segredo.
- `chave`: material criptografico de assinatura/cifra.

## HASH

| Operacao | Material | Codigo | Controles atuais | Risco residual |
|---|---|---|---|---|
| Hash SHA-256 de segredo recebido via API (historico, endpoint removido) | segredo bruto -> derivado | `Api/Endpoints/Cryptography/HashSecret.cs` | Nonce obrigatorio e consumido antes | Endpoint removido do runtime MVP |
| Hash SHA-256 para witness de prova | segredo bruto -> derivado | `Infrastructure/Zk/Witness/DefaultZkWitnessGenerator.cs:20-27` | Entrada validada no fluxo de comando; hash publico normalizado (`:34-52`) | `SecretBase64` existe em memoria durante geracao do witness |
| Comparacao hash(segredo) vs hash publico | derivado | `Infrastructure/Zk/Backends/InProcessZkBackend.cs:48-53` | `CryptographicOperations.FixedTimeEquals` (`:51`) | Backend in-process (nao substitui stack zk externa) |

## MAC

| Operacao | Material | Codigo | Controles atuais | Risco residual |
|---|---|---|---|---|
| HMAC-SHA256 para assinatura do challenge | chave cliente + payload de nonce | `Api/Endpoints/Users/NonceChallengeRespond.cs:109-121` | Compare em tempo fixo (`:121`), janela de clock skew (`:134-146`), consumo de nonce (`:72-77`) | Segredo do cliente depende de configuracao segura em `AuthChallenge:ClientSecrets` |
| MAC da prova local in-process | chave local `_hmacKey` + `hashPublic|meta` | `Infrastructure/Zk/Backends/InProcessZkBackend.cs:56-71` e `:152-165` | Verificacao de MAC com compare em tempo fixo (`:137-144`), schema version (`:106-109`) | Chave local precisa ser forte em prod (`:35-39`) |
| Assinatura de JWT (HMAC-SHA256) | chave JWT | `Infrastructure/Authentication/Jwt/JwtTokenProvider.cs:24-25` e `:49-57` | Token com exp/notBefore (`:47-55`) | Segredo JWT continua ponto critico de hardening operacional |

## SCALAR

| Operacao | Material | Codigo | Controles atuais | Risco residual |
|---|---|---|---|---|
| Igualdade de elementos de campo Fp/Fr | derivado de dados de curva | `Infrastructure/Zk/Crypto/FieldElement.cs:38`, `:67`, `:137-151` | `ConstantTimeEquals` byte a byte | Outras operacoes aritmeticas usam `BigInteger` (nao constant-time) |
| Multiplicacao escalar G1 | scalar | `Infrastructure/Zk/Crypto/RealCurvePoints.cs:93-97` e `:131-159` | Validacoes de curva/subgrupo em outros pontos do fluxo | `MultiplyUnchecked` com branches por bit (`:147-156`) |
| Multiplicacao escalar G2 | scalar | `Infrastructure/Zk/Crypto/RealCurvePoints.cs:262-271` e `:320-348` | Check de subgrupo (`:284-312`) | Mesmo risco de timing por branch no loop |
| Pairing (Miller loop + final exponentiation) | pontos/escalares derivados | `Infrastructure/Zk/Crypto/PairingReferenceEngine.cs:33-67` e `:69-87` | Validacao de pontos para pairing (`:40-41`) | Implementacao de referencia; nao orientada a constant-time extremo |

## NONCE

| Operacao | Material | Codigo | Controles atuais | Risco residual |
|---|---|---|---|---|
| Emissao de challenge nonce | nonce aleatorio | `Api/Endpoints/Users/NonceChallenge.cs:33-48` | RNG criptografico (`:35`), TTL (`:29-30`), `no-store` (`:26`, `:66-71`), rate limit | Escopo usa `clientId+ip` (`Api/Endpoints/Users/NonceChallengeScope.cs:5-11`) |
| Consumo de nonce no respond do challenge | nonce | `Api/Endpoints/Users/NonceChallengeRespond.cs:72-77` | Consumo one-time e skew window (`:64-67`, `:139-145`) | Dependencia de relogio (clock skew) e configuracao |
| Consumo de nonce no verify do challenge | nonce | `Api/Endpoints/Users/NonceChallengeVerify.cs:30-35` | One-time consume | Endpoint anonimo exige rate limit |
| Consumo de nonce nas rotas ZK | nonce | `Api/Endpoints/Cryptography/HashSecret.cs:35-37`, `Prove.cs:28-30`, `Verify.cs:28-30` | Bloqueia replay antes de hash/prove/verify | Requer cliente seguir fluxo de challenge |
| Armazenamento nonce com TTL/capacidade | nonce | `Infrastructure/Security/InMemoryNonceStore.cs:32-81`, `:83-120` | TTL, prune e max entries (`:21-29`, `:122-151`) | Store em memoria (sem persistencia distribuida) |
| Nonce para AES-GCM de segredo em repouso | nonce de cifragem | `Infrastructure/Security/AesGcmSecretProtector.cs:83-101` | RNG criptografico (`:92`), deduplicacao via nonce store (`:93`) | Janela limitada por `MaxNonceGenerationAttempts` |

## PROOF BYTES

| Operacao | Material | Codigo | Controles atuais | Risco residual |
|---|---|---|---|---|
| Geracao de bytes de prova | derivado (hash+meta+MAC) | `Infrastructure/Zk/Backends/InProcessZkBackend.cs:63-75` | `SchemaVersion` (`:64`), MAC no payload (`:71`) | Nao e prova zk real; backend local |
| Serializacao para transporte HTTP | proof bytes (base64) | `Application/Cryptography/ProveCommandHandler.cs:28-30` | Validacao de entrada antes do fluxo (`:15-24`) | Base64 trafega no payload HTTP (esperado) |
| Contrato de verificacao recebe `Proof` string | proof bytes (base64) | `Application/Contracts/Zk/VerificationRequest.cs:3-7` | Validacao de campos obrigatorios (`Application/Cryptography/ZkInputValidation.cs:32-55`) | Requer limite de tamanho operacional (gateway) |
| Decodificacao e validacao de prova | proof bytes (base64/json) | `Infrastructure/Zk/Backends/InProcessZkBackend.cs:81-99`, `:101-109`, `:111-149` | Decode seguro, parse seguro, schema check, MAC check fixed-time (`:143`) | Sem stack externa (circom/gnark/halo2) |
| Estrutura de prova local | derivado | `Infrastructure/Zk/Backends/InProcessZkBackend.cs:286-297` | Payload nao inclui segredo em claro | Integridade depende da chave HMAC local |

## Controles transversais relevantes

| Controle | Codigo | Efeito |
|---|---|---|
| Mascara de headers/query sensiveis em logs | `Api/Program.cs:156-179`, `Api/Logging/SensitiveDataMasker.cs:6-70` | Evita logar `authorization`, `token`, `secret`, `api-key`, etc |
| Tratamento global de excecao sem payload sensivel | `Api/Infrastructure/GlobalExceptionHandler.cs:17-23` e `:24-38` | Loga metadados (trace/correlation/path/tipo), nao loga corpo/segredo |
| `no-store` para respostas sensiveis | `NonceChallenge.cs:66-71`, `NonceChallengeRespond.cs:176-181`, `NonceChallengeVerify.cs:67-72`, `SecretStore.cs:691-696` | Reduz risco de cache indevido |
| Rate limit em rotas sensiveis | `Api/Program.cs` (policies) e endpoints (`RequireRateLimiting`) | Reduz abuso e brute force |

## Gaps principais (prioridade)

1. `scalar` em `RealCurvePoints` e aritmetica com `BigInteger` ainda nao sao constant-time de ponta a ponta.
2. Store de nonce e local/in-memory; em escala horizontal precisa backend distribuido.
3. Prover in-process atual e fallback operacional, nao prova zk de producao.
4. Endpoint de entrega controlada de segredo ainda retorna `Value` em claro por contrato (`Api/Endpoints/Vault/SecretStore.cs:436-443`); manter governanca/auditoria forte.
