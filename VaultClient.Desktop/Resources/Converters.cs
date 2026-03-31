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
