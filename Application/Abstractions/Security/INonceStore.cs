namespace Application.Abstractions.Security;

public interface INonceStore
{
    ValueTask<bool> TryAddAsync(
        string scope,
        ReadOnlyMemory<byte> nonce,
        CancellationToken cancellationToken = default);

    ValueTask<bool> TryConsumeAsync(
        string scope,
        ReadOnlyMemory<byte> nonce,
        CancellationToken cancellationToken = default);
}
