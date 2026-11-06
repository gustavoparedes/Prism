using System.IO;
using Syncfusion.Licensing;
using WpfApplication = System.Windows.Application;

namespace Prism.Wpf;

public partial class App : WpfApplication
{
    internal const double DefaultFontSize = 14;

    public App()
    {
        var icon = System.Windows.Media.Imaging.BitmapFrame.Create(
            new Uri("pack://application:,,,/Prism.Wpf;component/Assets/prism.ico"));
        icon.Freeze();
        System.Windows.EventManager.RegisterClassHandler(typeof(System.Windows.Window),
            System.Windows.FrameworkElement.LoadedEvent,
            new System.Windows.RoutedEventHandler((sender, args) =>
            {
                if (sender is System.Windows.Window window && ReferenceEquals(args.OriginalSource, window)
                    && window.Icon == null)
                    window.SetCurrentValue(System.Windows.Window.IconProperty, icon);
            }));
        RuntimeDiagnostics.Initialize();
        DispatcherUnhandledException += (_, e) => RuntimeDiagnostics.Record("DispatcherUnhandledException", e.Exception.ToString());
    }

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);
        RegisterSyncfusionLicense();

        string? casePath = e.Args.FirstOrDefault(arg =>
            string.Equals(Path.GetExtension(arg), ".pri", StringComparison.OrdinalIgnoreCase)
            && File.Exists(arg));

        ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown;
        StartAction action = StartAction.None;
        if (casePath == null)
        {
            var start = new StartDialog { WindowStartupLocation = System.Windows.WindowStartupLocation.CenterScreen };
            if (start.ShowDialog() != true || start.Selection == StartAction.Exit)
            {
                Shutdown();
                return;
            }
            action = start.Selection;
        }

        var window = new MainWindow(casePath);
        window.PrepareStartup();
        MainWindow = window;
        ShutdownMode = System.Windows.ShutdownMode.OnMainWindowClose;
        window.Show();
        window.RunStartupAction(action);
    }

    private static void RegisterSyncfusionLicense()
    {
        string? license = Environment.GetEnvironmentVariable("PRISM_SYNCFUSION_LICENSE_KEY")
            ?? Environment.GetEnvironmentVariable("SYNCFUSION_LICENSE_KEY");

        if (string.IsNullOrWhiteSpace(license))
        {
            using var embedded = typeof(App).Assembly.GetManifestResourceStream("Prism.RuntimeLicense");
            if (embedded != null) license = new StreamReader(embedded).ReadToEnd().Trim();
        }

        string localLicensePath = Path.Combine(AppContext.BaseDirectory, "syncfusion-license.txt");
        if (string.IsNullOrWhiteSpace(license) && File.Exists(localLicensePath))
            license = File.ReadAllText(localLicensePath).Trim();

        if (!string.IsNullOrWhiteSpace(license))
            SyncfusionLicenseProvider.RegisterLicense(license);
    }
}
