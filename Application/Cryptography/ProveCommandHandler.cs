using Application.Abstractions.Cryptography;
using Application.Abstractions.Messaging.Handlers;
using Shared;

namespace Application.Cryptography;

internal sealed class ProveCommandHandler : ICommandHandler<ProveCommand, string>
{
    private readonly IZkProofService _zkProofService;

    public ProveCommandHandler(IZkProofService zkProofService) => _zkProofService = zkProofService;

    public async Task<Result<string>> Handle(ProveCommand command, CancellationToken cancellationToken = default)
    {
        var validationError = ZkInputValidation.ValidatePreimage(
            command.Request.Secret,
            command.Request.HashPublic,
            command.Request.ClientId,
            command.Request.Nonce);
        
        if (validationError is not null)
        {
            return Result.Failure<string>(validationError);
        }

        try
        {
            var proof = await _zkProofService.GenerateProofAsync(command.Request, cancellationToken);
            var proofBase64 = Convert.ToBase64String(proof.Proof);
            return Result.Success(proofBase64);
        }
        catch (InvalidOperationException)
        {
            return Result.Failure<string>(ZkErrors.InvalidInput);
        }
        catch (HttpRequestException)
        {
            return Result.Failure<string>(ZkErrors.BackendUnavailable);
        }
    }
}
