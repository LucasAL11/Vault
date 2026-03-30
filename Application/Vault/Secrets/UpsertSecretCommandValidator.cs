using FluentValidation;

namespace Application.Vault.Secrets;

public sealed class UpsertSecretCommandValidator : AbstractValidator<UpsertSecretCommand>
{
    public UpsertSecretCommandValidator()
    {
        RuleFor(x => x.VaultId)
            .NotEmpty().WithMessage("VaultId is required.");

        RuleFor(x => x.Name)
            .NotEmpty().WithMessage("Secret name is required.")
            .MaximumLength(120).WithMessage("Secret name cannot exceed 120 characters.");

        RuleFor(x => x.Value)
            .NotEmpty().WithMessage("Secret value is required.");

        RuleFor(x => x.Actor)
            .NotEmpty().WithMessage("Actor is required.");
    }
}
