using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Prism.Wpf;

public sealed class SearchInputWidthConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        new GridLength(value is double width && double.IsFinite(width) ? Math.Clamp(width - 850, 128, 420) : 128);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
