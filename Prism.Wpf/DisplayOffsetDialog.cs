using System.Windows;
using System.Windows.Controls;

namespace Prism.Wpf;

internal sealed class DisplayOffsetDialog : Window
{
    public EvidenceTimeZoneChoice Selection { get; private set; }

    public DisplayOffsetDialog(EvidenceTimeZoneChoice current)
    {
        Selection = current;
        FontSize = App.DefaultFontSize;
        Title = UiText.DisplayUtcOffset;
        Width = 720;
        MaxWidth = Math.Max(320,SystemParameters.WorkArea.Width-48);
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;

        var choices = EvidenceTimeZoneChoice.BuildChoices();
        var offsets = new ComboBox
        {
            Name = "OffsetChoices", ItemsSource = choices,
            SelectedItem = choices.FirstOrDefault(c => c.Zone.Id == current.Zone.Id) ?? choices.First(c=>c.Zone.BaseUtcOffset==current.Zone.BaseUtcOffset),
            MinHeight = 34, MaxDropDownHeight = 400, IsTextSearchEnabled = true,
            Margin = new Thickness(0, 6, 0, 22)
        };
        System.Windows.Controls.TextSearch.SetTextPath(offsets,"DisplayName");
        offsets.SetBinding(ToolTipProperty,new System.Windows.Data.Binding("SelectedItem.DisplayName"){Source=offsets});
        var label = new Label { Content = UiText.UtcOffset, Target = offsets, Padding = new Thickness(0) };
        var ok = new Button { Name = "ConfirmOffset", Content = UiText.Ok, IsDefault = true, MinWidth = 80, MinHeight = 30 };
        var cancel = new Button { Name = "CancelOffset", Content = UiText.Cancel, IsCancel = true, MinWidth = 80, MinHeight = 30, Margin = new Thickness(8, 0, 0, 0) };
        ok.Click += (_, _) =>
        {
            if (offsets.SelectedItem is not EvidenceTimeZoneChoice choice) return;
            Selection = choice;
            DialogResult = true;
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        var root = new StackPanel { Margin = new Thickness(20) };
        root.Children.Add(label);
        root.Children.Add(offsets);
        root.Children.Add(new TextBlock { Text="Display only: applies the listed UTC offset as a fixed offset. Stored timestamps remain unchanged.", TextWrapping=TextWrapping.Wrap, Foreground=System.Windows.Media.Brushes.DimGray, Margin=new Thickness(0,0,0,18) });
        root.Children.Add(buttons);
        Content = root;
        Loaded += (_, _) => offsets.Focus();
    }
}
