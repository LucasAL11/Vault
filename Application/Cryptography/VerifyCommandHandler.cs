using Application.Abstractions.Cryptography;
using Application.Abstractions.Messaging.Handlers;
using Shared;
using System.Net.Http;

namespace Application.Cryptography;

public sealed class VerifyCommandHandler : ICommandHandler<VerifyCommand, bool>
{
    private readonly IZkProofService _zkProofService;

    public VerifyCommandHandler(IZkProofService zkProofService) => _zkProofService = zkProofService;

    public async Task<Result<bool>> Handle(VerifyCommand command, CancellationToken cancellationToken = default)
    {
        var validationError = ZkInputValidation.ValidateVerification(
            command.Request.Proof,
            command.Request.HashPublic,
            command.Request.ClientId,
            command.Request.Nonce);
        
        if (validationError is not null)
        {
            return Result.Failure<bool>(validationError);
        }

        try
        {
            var isValid = await _zkProofService.VerifyProofAsync(command.Request, cancellationToken);
            return isValid
                ? Result.Success(true)
                : Result.Failure<bool>(ZkErrors.InvalidProof);
        }
        catch (InvalidOperationException)
        {
            return Result.Failure<bool>(ZkErrors.InvalidInput);
        }
        catch (HttpRequestException)
        {
            return Result.Failure<bool>(ZkErrors.BackendUnavailable);
        }
    }
}
