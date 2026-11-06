using System.Globalization;
using System.Windows.Data;

namespace Prism.Wpf;

public sealed class NavigationHeaderWidthConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        double inset = parameter is string text && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out double requested) ? requested : 34;
        return value is double width ? Math.Max(100, width - inset) : 180d;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
