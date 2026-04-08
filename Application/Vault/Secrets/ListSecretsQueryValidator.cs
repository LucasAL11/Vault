using FluentValidation;

namespace Application.Vault.Secrets;

public sealed class ListSecretsQueryValidator : AbstractValidator<ListSecretsQuery>
{
    public ListSecretsQueryValidator()
    {
        RuleFor(x => x.VaultId)
            .NotEmpty().WithMessage("VaultId is required.");

        RuleFor(x => x.Page)
            .GreaterThan(0).WithMessage("page must be greater than zero.");

        RuleFor(x => x.PageSize)
            .InclusiveBetween(1, 100).WithMessage("pageSize must be between 1 and 100.");

        RuleFor(x => x.Name)
            .MaximumLength(120).WithMessage("name filter cannot exceed 120 characters.")
            .When(x => x.Name is not null);
    }
}
