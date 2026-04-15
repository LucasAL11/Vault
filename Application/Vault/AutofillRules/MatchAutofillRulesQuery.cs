using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AutofillRules;

/// <summary>
/// Procura regras de autofill que correspondam a uma URL específica.
/// Usado pela extensão Chrome para determinar quais credenciais preencher.
/// </summary>
public sealed record MatchAutofillRulesQuery(string Url) : IQuery<IReadOnlyCollection<AutofillRuleDto>>;

internal sealed class MatchAutofillRulesQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<MatchAutofillRulesQuery, IReadOnlyCollection<AutofillRuleDto>>
{
    public async Task<Result<IReadOnlyCollection<AutofillRuleDto>>> Handle(MatchAutofillRulesQuery query, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(query.Url))
        {
            return Result.Failure<IReadOnlyCollection<AutofillRuleDto>>(
                VaultErrors.InvalidUrlPattern());
        }

        var url = query.Url.Trim().ToLowerInvariant();

        // Load active rules and match in memory (supports wildcard patterns)
        var rules = await dbContext.AutofillRules
            .AsNoTracking()
            .Where(x => x.IsActive)
            .Select(x => new AutofillRuleDto(
                x.Id,
                x.VaultId,
                x.UrlPattern,
                x.Login,
                x.SecretName,
                x.IsActive,
                x.CreatedAt))
            .ToListAsync(cancellationToken);

        var matched = rules
            .Where(r => MatchesUrl(url, r.UrlPattern))
            .ToArray();

        return matched;
    }

    /// <summary>
    /// Verifica se a URL corresponde ao padrão.
    /// Suporta wildcard '*' no final (ex: "https://erp.empresa.com/*").
    /// Também faz match exato e por prefixo de hostname.
    /// </summary>
    private static bool MatchesUrl(string url, string pattern)
    {
        var normalizedPattern = pattern.Trim().ToLowerInvariant();

        // Wildcard no final: "https://example.com/*" matches "https://example.com/login"
        if (normalizedPattern.EndsWith("*"))
        {
            var prefix = normalizedPattern[..^1];
            if (url.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
            // prefix didn't match (different scheme/port) — fall through to hostname matching
        }

        // Match exato
        if (string.Equals(url, normalizedPattern, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Match por hostname+porta: ignora scheme, compara host:port
        try
        {
            var patternRaw = normalizedPattern.TrimEnd('*').TrimEnd('/');
            var patternUri = new Uri(patternRaw.Contains("://") ? patternRaw : $"https://{patternRaw}");
            var urlUri    = new Uri(url.Contains("://") ? url : $"https://{url}");

            // Host deve ser igual; porta é ignorada — o padrão "https://host/*" deve
            // corresponder a "http://host:5080/" (scheme/porta diferentes mas mesmo host).
            return string.Equals(patternUri.Host, urlUri.Host, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
