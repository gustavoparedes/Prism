using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Calendar = System.Windows.Controls.Calendar;

namespace Prism.Wpf;

internal sealed class SearchDateTimeDialog : Window
{
    private readonly Calendar _calendar;
    private readonly ComboBox _hours;
    private readonly ComboBox _minutes;
    private readonly ComboBox _seconds;
    private readonly TextBlock _error;
    private readonly long _fraction;

    public DateTime Selection { get; private set; }

    public SearchDateTimeDialog(string title, DateTime current, string displayZone)
    {
        Selection = DateTime.SpecifyKind(current, DateTimeKind.Unspecified);
        _fraction = current.Ticks % TimeSpan.TicksPerSecond;
        Title = title;
        FontSize = App.DefaultFontSize;
        Width = 420;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        Background = Brushes.White;

        var root = new StackPanel { Margin = new Thickness(20) };
        root.Children.Add(new TextBlock { Text = title, FontSize = 18, FontWeight = FontWeights.SemiBold });
        root.Children.Add(new TextBlock
        {
            Text = displayZone,
            Foreground = Brushes.DimGray,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 6, 0, 10)
        });
        _calendar = new Calendar
        {
            Name = "BoundaryCalendar",
            SelectedDate = current.Date,
            DisplayDate = current.Date,
            SelectionMode = CalendarSelectionMode.SingleDate,
            HorizontalAlignment = HorizontalAlignment.Center,
            Language = System.Windows.Markup.XmlLanguage.GetLanguage("en-US")
        };
        root.Children.Add(_calendar);

        var time = new Grid { Margin = new Thickness(0, 14, 0, 4) };
        for (int i = 0; i < 3; i++)
            time.ColumnDefinitions.Add(new ColumnDefinition());
        _hours = AddTimeField(time, UiText.Hour, "BoundaryHours", 24, current.Hour, 0);
        _minutes = AddTimeField(time, UiText.Minute, "BoundaryMinutes", 60, current.Minute, 1);
        _seconds = AddTimeField(time, UiText.Second, "BoundarySeconds", 60, current.Second, 2);
        root.Children.Add(time);
        _error = new TextBlock
        {
            Foreground = Brushes.Firebrick,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 6, 0, 6)
        };
        root.Children.Add(_error);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var ok = new Button { Name = "ConfirmBoundary", Content = UiText.Ok, IsDefault = true, MinWidth = 85, MinHeight = 32 };
        var cancel = new Button { Name = "CancelBoundary", Content = UiText.Cancel, IsCancel = true, MinWidth = 85, MinHeight = 32, Margin = new Thickness(8, 0, 0, 0) };
        ok.Click += (_, _) =>
        {
            if (!TryReadSelection(out DateTime value))
            {
                _error.Text = UiText.InvalidSearchTime;
                return;
            }
            Selection = value;
            DialogResult = true;
        };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        root.Children.Add(buttons);
        Content = root;
    }

    internal bool TryReadSelection(out DateTime value)
    {
        value = default;
        if (_calendar.SelectedDate is not DateTime date
            || !Read(_hours, 24, out int hour)
            || !Read(_minutes, 60, out int minute)
            || !Read(_seconds, 60, out int second))
            return false;
        value = DateTime.SpecifyKind(date.Date.AddHours(hour).AddMinutes(minute).AddSeconds(second).AddTicks(_fraction), DateTimeKind.Unspecified);
        return true;
    }

    private static bool Read(ComboBox box, int limit, out int value) =>
        int.TryParse(box.Text, NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= 0 && value < limit;

    private static ComboBox AddTimeField(Grid row, string title, string name, int limit, int current, int column)
    {
        var panel = new StackPanel { Margin = new Thickness(column == 0 ? 0 : 8, 0, 0, 0) };
        var box = new ComboBox
        {
            Name = name,
            ItemsSource = Enumerable.Range(0, limit).Select(value => value.ToString("D2", CultureInfo.InvariantCulture)).ToArray(),
            IsEditable = true,
            IsTextSearchEnabled = false,
            MinHeight = 32,
            MaxDropDownHeight = 220,
            Text = current.ToString("D2", CultureInfo.InvariantCulture)
        };
        panel.Children.Add(new Label { Content = title, Target = box, Padding = new Thickness(0, 0, 0, 5) });
        panel.Children.Add(box);
        Grid.SetColumn(panel, column);
        row.Children.Add(panel);
        return box;
    }
}
