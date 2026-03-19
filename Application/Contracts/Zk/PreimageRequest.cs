namespace Application.Contracts.Zk;

/// <summary>
/// Inputs from API kept as strings to avoid JSON base64 binding errors; conversion happens downstream.
/// </summary>
public sealed record PreimageRequest(
    string Secret,
    string HashPublic,
    string ClientId,
    string Nonce);
