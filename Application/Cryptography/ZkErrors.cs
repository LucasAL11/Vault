using Shared;

namespace Application.Cryptography;

public static class ZkErrors
{
    public static readonly Error SecretRequired = Error.BadRequest(
        "Zk.SecretRequired",
        "Campo 'secret' obrigatorio.");

    public static readonly Error HashPublicRequired = Error.BadRequest(
        "Zk.HashPublicRequired",
        "Campo 'hashPublic' obrigatorio.");

    public static readonly Error ProofRequired = Error.BadRequest(
        "Zk.ProofRequired",
        "Campo 'proof' obrigatorio.");

    public static readonly Error InvalidInput = Error.BadRequest(
        "Zk.InvalidInput",
        "Entradas ZK invalidas. Use hashPublic em base64 ou hex e garanta consistencia com o segredo.");

    public static readonly Error InvalidProof = Error.Unauthorized(
        "Zk.InvalidProof",
        "A prova ZK apresentada eh invalida ou nao pode ser verificada.");

    public static readonly Error BackendUnavailable = Error.Problem(
        "Zk.BackendUnavailable",
        "Servico de prova/verificacao ZK indisponivel no momento.");
}
