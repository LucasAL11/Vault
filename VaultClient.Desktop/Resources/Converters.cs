using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace VaultClient.Desktop.Resources;

[ValueConversion(typeof(bool), typeof(Visibility))]
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

[ValueConversion(typeof(bool), typeof(Visibility))]
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

[ValueConversion(typeof(string), typeof(Visibility))]
public sealed class NotEmptyToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => !string.IsNullOrWhiteSpace(value as string) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

[ValueConversion(typeof(int), typeof(Visibility))]
public sealed class ZeroToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Mostra o badge de "Expira em breve" se a data de expiracao e dentro de 7 dias.
/// </summary>
[ValueConversion(typeof(DateTimeOffset?), typeof(Visibility))]
public sealed class ExpiryWarningVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is DateTimeOffset expires)
        {
            var remaining = expires - DateTimeOffset.UtcNow;
            return remaining.TotalDays <= 7 && remaining.TotalDays > 0
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts null/non-null to Visibility. Non-null = Visible, null = Collapsed.
/// Pass "Inverse" as parameter to invert.
/// </summary>
[ValueConversion(typeof(object), typeof(Visibility))]
public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var isInverse = parameter is string s && s.Equals("Inverse", StringComparison.OrdinalIgnoreCase);
        var isNull = value is null;
        if (isInverse) isNull = !isNull;
        return isNull ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts status type string ("success", "error", "info") to a SolidColorBrush.
/// </summary>
[ValueConversion(typeof(string), typeof(SolidColorBrush))]
public sealed class StatusTypeToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush SuccessBrush = new((Color)ColorConverter.ConvertFromString("#A6E3A1"));
    private static readonly SolidColorBrush ErrorBrush   = new((Color)ColorConverter.ConvertFromString("#F38BA8"));
    private static readonly SolidColorBrush InfoBrush    = new((Color)ColorConverter.ConvertFromString("#89B4FA"));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value switch
        {
            "success" => SuccessBrush,
            "error"   => ErrorBrush,
            _         => InfoBrush
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts status type string to a background brush for the status bar.
/// </summary>
[ValueConversion(typeof(string), typeof(SolidColorBrush))]
public sealed class StatusTypeToBgBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush SuccessBg = new((Color)ColorConverter.ConvertFromString("#0D2B0D"));
    private static readonly SolidColorBrush ErrorBg   = new((Color)ColorConverter.ConvertFromString("#2B0D0D"));
    private static readonly SolidColorBrush InfoBg    = new((Color)ColorConverter.ConvertFromString("#181825"));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value switch
        {
            "success" => SuccessBg,
            "error"   => ErrorBg,
            _         => InfoBg
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Compara dois valores (via Equals) e retorna TrueBrush ou FalseBrush.
/// Uso: MultiBinding com [itemId, activeId] → brush do vault ativo na sidebar.
/// TrueBrush e FalseBrush são configurados no XAML.
/// </summary>
public sealed class GuidEqualToBrushConverter : IMultiValueConverter
{
    public Brush TrueBrush  { get; set; } = Brushes.Transparent;
    public Brush FalseBrush { get; set; } = Brushes.Transparent;

    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values.Length >= 2 && values[0] is not null && values[1] is not null
            && values[0].Equals(values[1]))
            return TrueBrush;
        return FalseBrush;
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Formata um DateTimeOffset como texto relativo ao momento atual.
/// Ex: "2m ago", "Yesterday 14:02", "Mar 28", "12/03/2024"
/// </summary>
[ValueConversion(typeof(DateTimeOffset), typeof(string))]
public sealed class RelativeTimeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not DateTimeOffset dt) return string.Empty;

        var now   = DateTimeOffset.UtcNow;
        var local = dt.ToLocalTime();
        var diff  = now - dt;

        if (diff.TotalMinutes < 1)   return "agora";
        if (diff.TotalMinutes < 60)  return $"{(int)diff.TotalMinutes}m atrás";
        if (diff.TotalHours   < 24)  return local.ToString("HH:mm");

        var today     = DateTimeOffset.Now.Date;
        var entryDate = local.Date;

        if (entryDate == today.AddDays(-1)) return $"Ontem {local:HH:mm}";
        if (entryDate.Year == today.Year)   return local.ToString("dd MMM", culture);

        return local.ToString("dd/MM/yyyy", culture);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converte o código de ação da auditoria num texto legível.
/// Ex: "SECRET_GET_VALUE" → "leu o valor"
/// </summary>
[ValueConversion(typeof(string), typeof(string))]
public sealed class AuditActionLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value switch
        {
            "SECRET_READ_METADATA"  => "visualizou metadados",
            "SECRET_GET_VALUE"      => "leu o valor",
            "SECRET_CREATED"        => "criou o segredo",
            "SECRET_UPDATED"        => "atualizou o segredo",
            "SECRET_UPSERTED"       => "rotacionou a senha",
            "SECRET_DELETE"         => "removeu o segredo",
            "SECRET_VERSION_REVOKE" => "revogou versão",
            "SECRET_REVOKE"         => "revogou o segredo",
            _                       => (value as string ?? "ação desconhecida").ToLowerInvariant()
                                            .Replace("secret_", "").Replace("_", " ")
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Extrai somente o nome de usuário de "DOMAIN\\user" ou "user@domain".
/// </summary>
[ValueConversion(typeof(string), typeof(string))]
public sealed class ActorNameConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not string actor || string.IsNullOrWhiteSpace(actor)) return "—";

        // DOMAIN\user → user
        var backslash = actor.LastIndexOf('\\');
        if (backslash >= 0) return actor[(backslash + 1)..];

        // user@domain → user
        var at = actor.IndexOf('@');
        if (at > 0) return actor[..at];

        return actor;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Checks if the bound VaultItem equals the ConverterParameter VaultItem (by Id).
/// Used to highlight the selected vault in the sidebar.
/// </summary>
[ValueConversion(typeof(object), typeof(SolidColorBrush))]
public sealed class SelectedItemBrushConverter : IMultiValueConverter
{
    private static readonly SolidColorBrush SelectedBrush   = new((Color)ColorConverter.ConvertFromString("#313244"));
    private static readonly SolidColorBrush UnselectedBrush = new((Color)ColorConverter.ConvertFromString("#00000000"));

    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values.Length == 2 && values[0] is not null && values[1] is not null && values[0].Equals(values[1]))
            return SelectedBrush;
        return UnselectedBrush;
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
