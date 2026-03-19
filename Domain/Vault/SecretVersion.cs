namespace Domain.vault;

/// <summary>
/// Representa uma versao imutavel de um segredo criptografado.
/// </summary>
public class SecretVersion
{
    public SecretVersion(
        Guid secretId,
        int version,
        byte[] cipherText,
        byte[] nonce,
        string keyReference,
        string contentType,
        DateTimeOffset? expires)
    {
        Id = Guid.NewGuid();
        SecretId = secretId;
        Version = version;
        CipherText = cipherText;
        Nonce = nonce;
        KeyReference = keyReference.Trim();
        ContentType = contentType.Trim();
        Expires = expires;
    }

    /// <summary>Identificador unico da versao.</summary>
    public Guid Id { get; init; }
    /// <summary>Identificador do segredo pai.</summary>
    public Guid SecretId { get; init; }
    /// <summary>Numero sequencial da versao.</summary>
    public int Version { get; init; }
    /// <summary>Conteudo criptografado do segredo.</summary>
    public byte[] CipherText { get; private set; }
    /// <summary>Nonce/IV usado no processo de criptografia.</summary>
    public byte[] Nonce { get; private set; }
    /// <summary>Referencia da chave utilizada para cifrar o conteudo.</summary>
    public string KeyReference { get; private set; }
    /// <summary>Tipo de conteudo original (ex.: text/plain, application/json).</summary>
    public string ContentType { get; init; } = "text/plain";
    /// <summary>Indica se a versao foi revogada.</summary>
    public bool IsRevoked { get; set; }

    /// <summary>Data de expiracao da versao, quando definida.</summary>
    public DateTimeOffset? Expires { get; init; }

    public void Revoke()
    {
        IsRevoked = true;
    }

    public void ReEncrypt(byte[] cipherText, byte[] nonce, string keyReference)
    {
        if (cipherText is null || cipherText.Length == 0)
        {
            throw new InvalidOperationException("CipherText is required.");
        }

        if (nonce is null || nonce.Length == 0)
        {
            throw new InvalidOperationException("Nonce is required.");
        }

        if (string.IsNullOrWhiteSpace(keyReference))
        {
            throw new InvalidOperationException("KeyReference is required.");
        }

        CipherText = cipherText;
        Nonce = nonce;
        KeyReference = keyReference.Trim();
    }
}
