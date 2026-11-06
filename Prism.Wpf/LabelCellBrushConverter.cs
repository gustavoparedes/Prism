using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Prism.Wpf;

internal sealed class LabelCellBrushConverter(IReadOnlyDictionary<string, Brush> colors, bool foreground) : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not string name || name.Length == 0 || !colors.TryGetValue(name, out var brush))
            return foreground ? Brushes.Black : Brushes.Transparent;
        if (!foreground) return brush;
        if (brush is not SolidColorBrush solid) return Brushes.Black;

        double Linear(double v) => v <= 0.04045 ? v / 12.92 : Math.Pow((v + 0.055) / 1.055, 2.4);
        double alpha = solid.Color.A / 255d;
        double Channel(byte c) => Linear((c / 255d) * alpha + 1 - alpha);
        double luminance = 0.2126 * Channel(solid.Color.R) + 0.7152 * Channel(solid.Color.G) + 0.0722 * Channel(solid.Color.B);
        return (luminance + 0.05) / 0.05 >= 1.05 / (luminance + 0.05) ? Brushes.Black : Brushes.White;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
