using Domain.vault;
using Xunit;

namespace Infrastructure.Tests;

public class SecretVersionReEncryptTests
{
    [Fact]
    public void ReEncrypt_ShouldUpdateCipherNonceAndKeyReference()
    {
        var version = new SecretVersion(
            secretId: Guid.NewGuid(),
            version: 1,
            cipherText: new byte[] { 1, 2, 3 },
            nonce: new byte[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            keyReference: "key-v1",
            contentType: "text/plain",
            expires: null);

        version.ReEncrypt(
            cipherText: new byte[] { 9, 9, 9, 9 },
            nonce: new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
            keyReference: "key-v2");

        Assert.Equal("key-v2", version.KeyReference);
        Assert.Equal(new byte[] { 9, 9, 9, 9 }, version.CipherText);
        Assert.Equal(new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }, version.Nonce);
    }

    [Fact]
    public void ReEncrypt_WithInvalidPayload_ShouldThrow()
    {
        var version = new SecretVersion(
            secretId: Guid.NewGuid(),
            version: 1,
            cipherText: new byte[] { 1, 2, 3 },
            nonce: new byte[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            keyReference: "key-v1",
            contentType: "text/plain",
            expires: null);

        Assert.Throws<InvalidOperationException>(() =>
            version.ReEncrypt(Array.Empty<byte>(), new byte[] { 1 }, "key-v2"));
    }
}
