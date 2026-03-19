using Shared;

namespace Domain.vault.Errors;

public class VaultErrors 
{
    public static readonly Error SecretNotFound 
        = Error.NotFound("Secret.NotFound", 
            "Segredo não encontrado");

    public static readonly Error SecretDisable
        = Error.Forbidden("Secret.Disable",
            "Segredo desabilitado");

    public static readonly Error VersionNotFound 
        = Error.NotFound("Secret.VersionNotFound",
        "Versao do segredo nao encontrada.");

    public static readonly Error VersionRevoked 
        = Error.Forbidden("Secret.VersionRevoked",
        "Versao do segredo foi revogada.");

    public static readonly Error VersionExpired 
        = Error.Forbidden("Secret.VersionExpired",
        "Versao do segredo expirada.");
}