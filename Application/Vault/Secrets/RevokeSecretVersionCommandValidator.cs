using FluentValidation;

namespace Application.Vault.Secrets;

public sealed class RevokeSecretVersionCommandValidator : AbstractValidator<RevokeSecretVersionCommand>
{
    public RevokeSecretVersionCommandValidator()
    {
        RuleFor(x => x.VaultId)
            .NotEmpty().WithMessage("VaultId is required.");

        RuleFor(x => x.Name)
            .NotEmpty().WithMessage("Secret name is required.");

        RuleFor(x => x.Version)
            .GreaterThan(0).WithMessage("Version must be greater than zero.");

        RuleFor(x => x.Reason)
            .NotEmpty().WithMessage("Reason is required.")
            .MaximumLength(500).WithMessage("Reason cannot exceed 500 characters.");

        RuleFor(x => x.Actor)
            .NotEmpty().WithMessage("Actor is required.");
    }
}
