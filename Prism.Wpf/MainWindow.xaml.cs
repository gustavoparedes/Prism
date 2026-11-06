using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using Syncfusion.UI.Xaml.Grid;
using OpenFolderDialog = Microsoft.Win32.OpenFolderDialog;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using Prism.Core.Acquisition;
using Prism.Core.Artifacts;
using Prism.Core.Cases;
using Prism.Core.Scanning;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;
using WpfMessageBox = System.Windows.MessageBox;

namespace Prism.Wpf;

public partial class MainWindow : Window
{
    private int _resultsPage;
    private int _resultsTotal;
    private const int ResultsPageSize = 500;
    private int _queryGeneration;
    private bool _overviewSearchActive;
    private readonly ShellDesignModel _model = ShellDesignModel.Create();
    private readonly List<ResultPreviewRow> _allRows = new();
    private readonly List<ResultPreviewRow> _caseRows = new();
    private readonly PrismCaseReader _caseReader = new();
    private readonly IPrismScanner _scanner = new CorePrismScanner();

    private const string RowObjectColumn = "__PrismRow";
    private string? _casePath;
    private EvidenceSelection? _selection;
    private EvidenceTimeZoneChoice _displayTimeZone = EvidenceTimeZoneChoice.Utc;
    private IReadOnlyDictionary<string, int> _caseArtifactCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyDictionary<string, int> _caseSystemProfileCounts = new Dictionary<string, int>();
    private string? _selectedArtifactName;
    private ArtifactNavGroup? _selectedCategory;
    private IReadOnlyDictionary<string,int> _overviewArtifactCounts=new Dictionary<string,int>();
    private IReadOnlyDictionary<string,int> _overviewProfileCounts=new Dictionary<string,int>();
    private string? _selectedSystemProfileId;
    private bool _startupDialogShown;
    private bool _searchDateDialogOpen;
    private bool _isProcessing;
    private bool _detailsExpanded = true;
    private double _expandedDetailsWidth = 390;

    public MainWindow()
        : this(null)
    {
    }

    public MainWindow(string? casePath)
    {
        InitializeComponent();
        DataContext = _model;
        InitializeTimeZoneControls();
        InitializeSearchControls();
        ClearResults();

        if (!string.IsNullOrWhiteSpace(casePath) && File.Exists(casePath))
        {
            _startupDialogShown = true;
            _casePath = casePath;
            UpdateCaseLabels();
            LoadCaseResults(casePath);
        }
    }

    private void InitializeSearchControls()
    {
        string now = DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        SearchFromBox.Text = now;
        SearchToBox.Text = now;
        TimeFilterCheckBox.IsChecked = false;
    }

    private void SearchDate_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not TextBox field) return;
        e.Handled = true;
        SelectSearchBoundary(field);
    }

    private void SearchDate_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (sender is not TextBox field) return;
        if (e.Key is not (Key.Enter or Key.Space or Key.F4)
            && !(e.Key == Key.System && e.SystemKey == Key.Down && Keyboard.Modifiers.HasFlag(ModifierKeys.Alt))) return;
        e.Handled = true;
        SelectSearchBoundary(field);
    }

    private void SelectSearchBoundary(TextBox field)
    {
        if (_searchDateDialogOpen) return;
        _searchDateDialogOpen = true;
        try
        {
            bool isEnd = ReferenceEquals(field, SearchToBox);
            DateTime current = DateTimeOffset.UtcNow.ToOffset(_displayTimeZone.Zone.BaseUtcOffset).DateTime;
            try
            {
                if (DisplayTime.ParseBoundary(field.Text, endOfDate: isEnd) is DateTimeOffset parsed)
                    current = parsed.ToOffset(_displayTimeZone.Zone.BaseUtcOffset).DateTime;
            }
            catch (FormatException)
            {
            }
            var dialog = new SearchDateTimeDialog(isEnd ? UiText.SearchEndDateTime : UiText.SearchStartDateTime, current, _displayTimeZone.DisplayName) { Owner = this };
            if (dialog.ShowDialog() != true) return;
            string format = dialog.Selection.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd HH:mm:ss" : "yyyy-MM-dd HH:mm:ss.fffffff";
            field.Text = dialog.Selection.ToString(format, CultureInfo.InvariantCulture);
            TimeFilterCheckBox.IsChecked = true;
        }
        finally
        {
            _searchDateDialogOpen = false;
        }
    }

    private void InitializeTimeZoneControls()
    {
        DisplayOffsetButton.Content = $"{UiText.DisplayUtcOffset}: {EvidenceTimeZoneChoice.FormatOffset(_displayTimeZone.Zone.BaseUtcOffset)}";
        DisplayOffsetButton.ToolTip = _displayTimeZone.DisplayName;
    }

    private TemporalDisplay DisplayTime => new(_displayTimeZone.Zone);

    internal void PrepareStartup() => _startupDialogShown = true;

    internal void RunStartupAction(StartAction action)
    {
        if (action == StartAction.NewCaseAndScan)
            NewCaseAndScan();
        else if (action == StartAction.OpenCase)
            OpenCase_Click(this, new RoutedEventArgs());
    }

    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        if (_startupDialogShown)
            return;

        _startupDialogShown = true;
        ShowStartDialog();
    }

    private void ShowStartDialog_Click(object sender, RoutedEventArgs e)
    {
        if (_isProcessing)
            return;

        ShowStartDialog();
    }

    private void ShowStartDialog()
    {
        var dialog = new StartDialog { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            if (string.IsNullOrWhiteSpace(_casePath))
                Application.Current.Shutdown();
            return;
        }

        switch (dialog.Selection)
        {
            case StartAction.Exit:
                Application.Current.Shutdown();
                break;
            case StartAction.NewCaseAndScan:
                NewCaseAndScan();
                break;
            case StartAction.OpenCase:
                OpenCase_Click(this, new RoutedEventArgs());
                break;
        }
    }

    private async void NewCaseAndScan()
    {
        if (_isProcessing || !ChooseNewCasePath())
            return;

        var sourceDialog = new SourceChoiceDialog { Owner = this };
        if (sourceDialog.ShowDialog() != true)
            return;

        switch (sourceDialog.Selection)
        {
            case StartAction.E01:
                SelectE01_Click(this, new RoutedEventArgs());
                break;
            case StartAction.AD1:
                SelectAd1();
                break;
            case StartAction.OfflineFolder:
                SelectOfflineFolder_Click(this, new RoutedEventArgs());
                break;
            case StartAction.LiveMachine:
                SelectLiveMachine_Click(this, new RoutedEventArgs());
                break;
        }

        if (_selection != null)
            await ProcessSelectedEvidenceAsync();
    }

    private bool ChooseNewCasePath()
    {
        var dialog = new SaveFileDialog
        {
            Title = UiText.CreateCaseTitle,
            Filter = PrismCaseFormat.DialogFilter,
            FileName = "PrismCase.pri",
            AddExtension = true,
            DefaultExt = PrismCaseFormat.Extension
        };

        if (dialog.ShowDialog(this) == true)
        {
            _casePath = PrismCaseFormat.EnsureExtension(dialog.FileName);
            _selection = null;
            ClearResults();
            UpdateCaseLabels();
            SetStatus(UiText.NewCaseSelected);
            return true;
        }
        return false;
    }

    private void OpenCase_Click(object sender, RoutedEventArgs e)
    {
        if (_isProcessing) return;
        var dialog = new OpenFileDialog
        {
            Title = UiText.OpenCaseTitle,
            Filter = PrismCaseFormat.DialogFilter + "|SQLite database (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog(this) == true)
        {
            _casePath = dialog.FileName;
            _selection = null;
            UpdateCaseLabels();
            LoadCaseResults(_casePath);
        }
    }

    private void DisplayOffset_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new DisplayOffsetDialog(_displayTimeZone) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.Selection == _displayTimeZone) return;
        var choice = dialog.Selection;
        _displayTimeZone = choice;
        InitializeTimeZoneControls();
        if (!string.IsNullOrWhiteSpace(_casePath) && File.Exists(_casePath))
        {
            LoadCaseResults(_casePath);
            SetStatus($"Display UTC offset changed to {choice.DisplayName}. Stored timestamps are unchanged.");
        }
    }

    private void SelectE01_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_casePath))
            return;

        var dialog = new OpenFileDialog
        {
            Title = UiText.SelectE01Title,
            Filter = "E01 evidence (*.E01;*.e01)|*.E01;*.e01|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog(this) == true)
        {
            _selection = EvidenceSelection.E01(dialog.FileName);
            UpdateCaseLabels();
            SetStatus(UiText.E01Selected);
        }
    }

    private void SelectAd1()
    {
        if (string.IsNullOrWhiteSpace(_casePath)) return;
        var dialog = new OpenFileDialog
        {
            Title = UiText.SelectAd1Title,
            Filter = "AD1 logical evidence (*.ad1)|*.ad1|All files (*.*)|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true) return;
        _selection = EvidenceSelection.AD1(dialog.FileName);
        UpdateCaseLabels();
        SetStatus(UiText.Ad1Selected);
    }

    private void SelectOfflineFolder_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_casePath))
            return;

        var dialog = new OpenFolderDialog
        {
            Title = UiText.SelectOfflineFolderTitle
        };

        if (dialog.ShowDialog(this) == true)
        {
            _selection = EvidenceSelection.OfflineFolder(dialog.FolderName);
            UpdateCaseLabels();
            SetStatus(UiText.OfflineFolderSelected);
        }
    }

    private void SelectLiveMachine_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_casePath))
            return;

        string volume = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        _selection = EvidenceSelection.LiveMachine(volume);
        UpdateCaseLabels();
        string message = LiveRegistryRawExtractor.IsRunningAsAdministrator()
            ? UiText.LiveModePrepared
            : UiText.LiveModeRequiresAdmin;
        SetStatus(string.Format(message, volume));
    }

    private async Task ProcessSelectedEvidenceAsync()
    {
        if (_isProcessing)
            return;

        if (string.IsNullOrWhiteSpace(_casePath))
            return;

        if (_selection == null)
        {
            WpfMessageBox.Show(this, UiText.SelectSourceBeforeProcessing, "Prism", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            RuntimeDiagnostics.Initialize();
            RuntimeDiagnostics.Record("ProcessRequested", $"Case={_casePath}; Source={_selection.Display}");
            _isProcessing = true;
            NewOpenButton.IsEnabled = false;
            RunStateText.Text = UiText.Processing;
            SetStatus(UiText.ProcessingEvidence);

            RuntimeDiagnostics.Record("InitialMetadataBegin", $"Case={_casePath}");
            WriteProcessingMetadata(_selection, "Started", startedUtc: DateTimeOffset.UtcNow, completedUtc: null, log: "");
            RuntimeDiagnostics.Record("InitialMetadataEnd", $"Case={_casePath}");
            UpdateCaseLabels();

            var progress = new ScanProgressState();
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            var progressTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
            void RefreshProgress(object? sender, EventArgs args)
            {
                var snapshot = progress.Snapshot();
                SetStatus(snapshot.Activity);
                RunStateText.Text = string.Format(UiText.ScanRunningStatus, elapsed.Elapsed.ToString(@"hh\:mm\:ss"), snapshot.Warnings);
                RunStateText.ToolTip = snapshot.LastWarning.Length > 0 ? snapshot.LastWarning : null;
            }
            progressTimer.Tick += RefreshProgress;
            progressTimer.Start();
            ScanResult result;
            try
            {
                RuntimeDiagnostics.Record("ScannerBegin", $"Case={_casePath}");
                result = await _scanner.ScanAsync(new ScanRequest(_casePath!, _selection), progress);
                RuntimeDiagnostics.Record("ScannerEnd", $"ExitCode={result.ExitCode}; Warnings={result.WarningCount}");
            }
            finally { progressTimer.Stop(); progressTimer.Tick -= RefreshProgress; }
            if (result.Success)
            {
                string status = result.WarningCount > 0 ? $"Completed with warnings ({result.WarningCount})" : "Completed";
                WriteProcessingMetadata(_selection, status, startedUtc: null, completedUtc: DateTimeOffset.UtcNow, log: result.Log);
                SetStatus(result.WarningCount > 0 ? status + ". See Processing log in Case information." : UiText.ProcessingFinished);
                LoadCaseResults(_casePath!);
            }
            else
            {
                WriteProcessingMetadata(_selection, $"Failed ({result.ExitCode})", startedUtc: null, completedUtc: DateTimeOffset.UtcNow, log: result.Log);
                SetStatus(string.Format(UiText.EngineFinishedWithCode, result.ExitCode));
                WpfMessageBox.Show(this, Tail(result.Log, 4000), UiText.EngineOutputTitle, MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            RuntimeDiagnostics.TryRecordFailure(ex, _casePath ?? "", () =>
            {
                if (_selection != null)
                    WriteProcessingMetadata(_selection, "Failed", startedUtc: null, completedUtc: DateTimeOffset.UtcNow, log: ex.ToString());
            });

            SetStatus(UiText.ProcessingError);
            WpfMessageBox.Show(this, $"{ex.Message}{Environment.NewLine}{Environment.NewLine}Local diagnostic log: {RuntimeDiagnostics.LogPath}", "Prism", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _isProcessing = false;
            _selection = null;
            NewOpenButton.IsEnabled = true;
            RunStateText.Text = UiText.Ready;
            RunStateText.ToolTip = null;
        }
    }

    private void ProcessingLog_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_casePath) || !File.Exists(_casePath))
            return;
        try
        {
            var text = new TextBox
            {
                Text = CaseProcessingLog.Read(_casePath), IsReadOnly = true,
                TextWrapping = TextWrapping.NoWrap, FontFamily = new FontFamily("Consolas"),
                FontSize = 14, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(12)
            };
            new Window
            {
                FontSize = App.DefaultFontSize,
                Owner = this, Title = UiText.ProcessingLog, Width = 1000, Height = 650,
                MinWidth = 600, MinHeight = 350, WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Content = text, Background = Background
            }.ShowDialog();
        }
        catch (Exception ex)
        {
            WpfMessageBox.Show(this, ex.Message, UiText.ProcessingLog, MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Search_Click(object sender, RoutedEventArgs e)
    {
        ClearArtifactSelection();
        ApplySearch();
    }

    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
            return;

        ClearArtifactSelection();
        ApplySearch();
        e.Handled = true;
    }

    private void ClearSearch_Click(object sender, RoutedEventArgs e)
    {
        SearchBox.Text = "";
        SearchFromBox.Text = "";
        SearchToBox.Text = "";
        TimeFilterCheckBox.IsChecked = false;
        RegexSearchCheckBox.IsChecked = false;
        LabelsFilterCheckBox.IsChecked = false;
        ApplySearch();
    }

    private void ClearArtifactSelection()
    {
        _resultsPage = 0;
        _selectedArtifactName = null;
        _selectedSystemProfileId = null;
        _selectedCategory=null;
        _model.SelectCategory(null);
        _model.SelectArtifact(null);
        AllArtifactsButton.Background = new SolidColorBrush(Color.FromRgb(232, 241, 248));
    }

    private void AllArtifacts_Click(object sender, RoutedEventArgs e)
    {
        ClearArtifactSelection();
        ApplySearch();
    }

    private void PreviousPage_Click(object sender, RoutedEventArgs e)
    {
        if (_resultsPage > 0) { _resultsPage--; ApplySearch(resetPage: false); }
    }

    private void NextPage_Click(object sender, RoutedEventArgs e)
    {
        if ((long)(_resultsPage + 1) * ResultsPageSize < _resultsTotal) { _resultsPage++; ApplySearch(resetPage: false); }
    }

    private void ArtifactNav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: ArtifactNavItem item })
            return;

        SelectArtifact(item);
    }

    private void ArtifactGroup_Click(object sender,RoutedEventArgs e)
    {
        e.Handled=true;
        if(sender is not FrameworkElement {DataContext:ArtifactNavGroup group} || string.IsNullOrWhiteSpace(_casePath))return;
        _selectedArtifactName=null;
        _selectedSystemProfileId=null;
        _selectedCategory=group;
        _model.SelectArtifact(null);
        _model.SelectCategory(group);
        AllArtifactsButton.Background=Brushes.White;
        ApplySearch();
    }

    private void UpdateCaseLabels()
    {
        CasePathText.Text = string.IsNullOrWhiteSpace(_casePath)
            ? UiText.NotSelected
            : _casePath;

        SourcePathText.Text = BuildSourceSummary();
    }

    private string BuildSourceSummary()
    {
        if (!string.IsNullOrWhiteSpace(_casePath) && File.Exists(_casePath))
        {
            IReadOnlyDictionary<string, string> metadata = PrismCaseDatabaseInitializer.ReadMetadata(_casePath);
            if (metadata.TryGetValue("source.kind", out string? kind) && !string.IsNullOrWhiteSpace(kind))
            {
                var lines = new List<string>
                {
                    $"Type: {kind}"
                };

                AddMetadataLine(lines, metadata, "source.name", "Name");
                AddMetadataLine(lines, metadata, "source.path", "Path");
                AddMetadataLine(lines, metadata, "source.hostname", "Hostname");
                AddMetadataLine(lines, metadata, "source.volume", "Volume");
                AddMetadataLine(lines, metadata, "source.size_bytes", "Size bytes");
                AddMetadataLine(lines, metadata, "source.last_write_utc", "Source last write UTC");
                AddMetadataLine(lines, metadata, "source.ad1.version", "AD1 version");
                AddMetadataLine(lines, metadata, "source.ad1.name", "Logical source");
                AddMetadataLine(lines, metadata, "source.ad1.scope", "Collection scope");
                AddMetadataLine(lines, metadata, "processing.status", "Status");
                AddMetadataLine(lines, metadata, "processing.started_utc", "Started UTC");
                AddMetadataLine(lines, metadata, "processing.completed_utc", "Completed UTC");
                AddMetadataLine(lines, metadata, "processing.duration", "Processing time");
                AddMetadataLine(lines, metadata, "processing.operator", "Operator");
                AddMetadataLine(lines, metadata, "processing.machine", "Processing machine");
                return string.Join(Environment.NewLine, lines);
            }
        }

        return _selection == null ? UiText.NotSelected : _selection.Display;
    }

    private static void AddMetadataLine(List<string> lines, IReadOnlyDictionary<string, string> metadata, string key, string label)
    {
        if (metadata.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
            lines.Add($"{label}: {value}");
    }

    private void WriteProcessingMetadata(
        EvidenceSelection selection,
        string status,
        DateTimeOffset? startedUtc,
        DateTimeOffset? completedUtc,
        string log)
    {
        if (string.IsNullOrWhiteSpace(_casePath))
            return;

        IReadOnlyDictionary<string, string> existingMetadata = File.Exists(_casePath)
            ? PrismCaseDatabaseInitializer.ReadMetadata(_casePath)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source.kind"] = SourceKindText(selection.Kind),
            ["source.path"] = selection.Path,
            ["source.name"] = SourceName(selection),
            ["processing.status"] = status,
            ["processing.operator"] = Environment.UserName,
            ["processing.machine"] = Environment.MachineName,
            ["processing.last_log"] = Tail(log ?? "", 2000)
        };

        if (startedUtc.HasValue)
            metadata["processing.started_utc"] = startedUtc.Value.ToString("O");
        if (completedUtc.HasValue)
            metadata["processing.completed_utc"] = completedUtc.Value.ToString("O");

        DateTimeOffset? effectiveStartedUtc = startedUtc ?? ReadMetadataTimestamp(existingMetadata, "processing.started_utc");
        DateTimeOffset? effectiveCompletedUtc = completedUtc ?? ReadMetadataTimestamp(existingMetadata, "processing.completed_utc");
        if (effectiveStartedUtc.HasValue && effectiveCompletedUtc.HasValue && effectiveCompletedUtc.Value >= effectiveStartedUtc.Value)
            metadata["processing.duration"] = FormatDuration(effectiveCompletedUtc.Value - effectiveStartedUtc.Value);

        if (selection.Kind == EvidenceKind.LiveMachine)
        {
            metadata["source.hostname"] = Environment.MachineName;
            metadata["source.volume"] = LiveRegistryRawExtractor.NormalizeVolumeRoot(selection.Path);
        }

        if (selection.Kind is EvidenceKind.E01 or EvidenceKind.AD1 && File.Exists(selection.Path))
        {
            var file = new FileInfo(selection.Path);
            metadata["source.size_bytes"] = file.Length.ToString(CultureInfo.InvariantCulture);
            metadata["source.last_write_utc"] = file.LastWriteTimeUtc.ToString("O");
        }
        else if (selection.Kind == EvidenceKind.OfflineFolder && Directory.Exists(selection.Path))
        {
            var directory = new DirectoryInfo(selection.Path);
            metadata["source.last_write_utc"] = directory.LastWriteTimeUtc.ToString("O");
        }

        PrismCaseDatabaseInitializer.DeleteMetadataKeys(
            _casePath,
            "evidence.timezone",
            "evidence.utc_offset",
            "evidence.utc_offset_minutes");
        PrismCaseDatabaseInitializer.UpsertMetadata(_casePath, metadata);
    }

    private static DateTimeOffset? ReadMetadataTimestamp(IReadOnlyDictionary<string, string> metadata, string key)
    {
        return metadata.TryGetValue(key, out string? value) &&
            DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset timestamp)
            ? timestamp.ToUniversalTime()
            : null;
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
            duration = TimeSpan.Zero;

        return duration.TotalHours >= 1
            ? $"{(int)duration.TotalHours:N0}h {duration.Minutes:00}m {duration.Seconds:00}s"
            : $"{duration.Minutes:N0}m {duration.Seconds:00}s";
    }

    private static string SourceKindText(EvidenceKind kind)
    {
        return kind switch
        {
            EvidenceKind.E01 => "E01/EWF image",
            EvidenceKind.AD1 => "AD1 logical image",
            EvidenceKind.OfflineFolder => "Folder",
            EvidenceKind.LiveMachine => "Live system",
            _ => kind.ToString()
        };
    }

    private static string SourceName(EvidenceSelection selection)
    {
        return selection.Kind switch
        {
            EvidenceKind.E01 or EvidenceKind.AD1 => Path.GetFileName(selection.Path),
            EvidenceKind.OfflineFolder => new DirectoryInfo(selection.Path).Name,
            EvidenceKind.LiveMachine => Environment.MachineName,
            _ => selection.Path
        };
    }

    private static string FormatUtcOffset(int offsetMinutes)
    {
        TimeSpan offset = TimeSpan.FromMinutes(offsetMinutes);
        string sign = offset < TimeSpan.Zero ? "-" : "+";
        offset = offset.Duration();
        return $"UTC{sign}{offset.Hours:00}:{offset.Minutes:00}";
    }

    private void LoadCaseResults(string casePath)
    {
        if (!File.Exists(casePath))
        {
            ClearResults();
            SetStatus(UiText.CaseDoesNotExist);
            return;
        }

        CaseLoadResult result = _caseReader.Load(casePath, DisplayTime, perTableLimit: 0, totalLimit: 0);

        _caseArtifactCounts = result.ArtifactCounts;
        _caseSystemProfileCounts = result.SystemProfileCounts;
        _caseRows.Clear();
        _allRows.Clear();
        RegistryCountText.Text = result.RegistryCount.ToString("N0");
        LocalCountText.Text = result.LocalArtifactCount.ToString("N0");
        _model.UpdateArtifactCounts(_caseArtifactCounts);
        _model.UpdateSystemProfileCounts(_caseSystemProfileCounts);
        ClearArtifactSelection();
        ResultsTitleText.Text = UiText.Results;
        RunStateText.Text = File.Exists(casePath) ? UiText.CaseLoadedState : UiText.Ready;
        UpdateCaseLabels();
        ApplySearch();
    }

    private void SelectArtifact(ArtifactNavItem item)
    {
        if (string.IsNullOrWhiteSpace(_casePath) || !File.Exists(_casePath))
            return;

        _selectedCategory=null;
        _model.SelectCategory(null);
        _model.SelectArtifact(item);
        _selectedSystemProfileId = item.SystemProfileId;
        _selectedArtifactName = item.SystemProfileId == null ? item.Name : SystemProfileCatalog.Get(item.SystemProfileId).ArtifactName;
        AllArtifactsButton.Background = Brushes.White;
        ApplySearch();
    }

    private async void ApplySearch(bool resetPage = true)
    {
        if (ResultsGrid == null || string.IsNullOrWhiteSpace(_casePath) || !File.Exists(_casePath))
            return;
        if (resetPage) _resultsPage = 0;
        int generation = ++_queryGeneration;
        string casePath = _casePath;
        string? selectedArtifact = _selectedArtifactName;
        string? selectedProfile = _selectedSystemProfileId;
        var selectedCategory=_selectedCategory;
        int pageIndex = _resultsPage;
        TemporalDisplay displayOffset = DisplayTime;
        SearchCriteria criteria = GetSearchCriteria();
        if (!string.IsNullOrWhiteSpace(criteria.RegexError))
        {
            Mouse.OverrideCursor = null;
            _resultsTotal = 0;
            PreviousPageButton.IsEnabled = false;
            NextPageButton.IsEnabled = false;
            PageStatusText.Text = "0-0 of 0";
            BuildResultsGrid(Array.Empty<ResultPreviewRow>(), criteria);
            ResultsTitleText.Text = "Search results: 0 hits";
            SetStatus($"Invalid search: {criteria.RegexError}");
            return;
        }
        try
        {
            Mouse.OverrideCursor = Cursors.Wait;
            PreviousPageButton.IsEnabled = false;
            NextPageButton.IsEnabled = false;
            if (selectedProfile != null)
            {
                var profile = await Task.Run(() => _caseReader.LoadSystemProfileRows(casePath, selectedProfile, displayOffset));
                if (generation != _queryGeneration) return;
                var rows = profile.Rows.Where(row => !criteria.IsActive || MatchesSearch(row, criteria)).ToArray();
                _allRows.Clear(); _allRows.AddRange(rows); _resultsTotal = rows.Length;
                if (!criteria.IsActive)
                {
                    _model.UpdateArtifactCounts(_caseArtifactCounts);
                    _model.UpdateSystemProfileCounts(_caseSystemProfileCounts);
                    AllArtifactsButton.Content = $"{UiText.AllArtifacts}: {_caseArtifactCounts.Values.Sum():N0} hits";
                }
                _model.SetSystemProfileCount(selectedProfile, rows.Length);
                ResultsPager.Visibility = Visibility.Collapsed;
                ResultsTitleText.Text = $"{SystemProfileCatalog.Get(selectedProfile).Name}: {rows.Length:N0} hits";
                BuildResultsGrid(rows, criteria);
                SetStatus(rows.Length == 0 ? ResultsTitleText.Text + ". No matching records stored in this case." : ResultsTitleText.Text);
                return;
            }
            if (!criteria.IsActive && _selectedArtifactName != null)
            {
                var artifact = await Task.Run(() => _caseReader.LoadArtifactRows(casePath, selectedArtifact!, displayOffset, int.MaxValue));
                if (generation != _queryGeneration) return;
                _allRows.Clear();
                _allRows.AddRange(artifact.Rows);
                _model.UpdateArtifactCounts(_caseArtifactCounts);
                _model.UpdateSystemProfileCounts(_caseSystemProfileCounts);
                AllArtifactsButton.Content = $"{UiText.AllArtifacts}: {_caseArtifactCounts.Values.Sum():N0} hits";
                ResultsPager.Visibility = Visibility.Collapsed;
                ResultsTitleText.Text = $"{_selectedArtifactName}: {artifact.TotalCount:N0} hits";
                BuildResultsGrid(artifact.Rows, criteria);
                SetStatus(ResultsTitleText.Text);
                return;
            }
            ResultsPager.Visibility = selectedArtifact == null ? Visibility.Collapsed : Visibility.Visible;
            var page = await Task.Run(() => selectedArtifact == null
                ? _caseReader.LoadOverviewRows(casePath, displayOffset, criteria.IsActive ? row => MatchesSearch(row, criteria) : null)
                : _caseReader.LoadOverviewPage(casePath, displayOffset, pageIndex, ResultsPageSize,
                    criteria.IsActive ? row => MatchesSearch(row, criteria) : null, selectedArtifact));
            if (generation != _queryGeneration) return;
            _overviewArtifactCounts=page.ArtifactCounts;
            _overviewProfileCounts=page.SystemProfileCounts;
            var displayedRows=selectedCategory==null?page.Rows:page.Rows.Where(selectedCategory.Contains).ToArray();
            int displayedTotal=selectedCategory==null?page.TotalCount:displayedRows.Count;
            _overviewSearchActive = criteria.IsActive;
            _allRows.Clear();
            _allRows.AddRange(displayedRows);
            _resultsTotal = displayedTotal;
            _model.UpdateArtifactCounts(criteria.IsActive ? page.ArtifactCounts : _caseArtifactCounts);
            _model.UpdateSystemProfileCounts(criteria.IsActive ? page.SystemProfileCounts : _caseSystemProfileCounts);
            string name = selectedCategory?.Name ?? _selectedArtifactName ?? (criteria.IsActive ? "Search results" : UiText.AllArtifacts);
            ResultsTitleText.Text = $"{name}: {displayedTotal:N0} hits";
            AllArtifactsButton.Content = $"{UiText.AllArtifacts}: {page.ArtifactCounts.Values.Sum():N0} hits";
            int first = page.TotalCount == 0 ? 0 : _resultsPage * ResultsPageSize + 1;
            PageStatusText.Text = $"{first:N0}-{first + page.Rows.Count - (page.Rows.Count > 0 ? 1 : 0):N0} of {page.TotalCount:N0}";
            PreviousPageButton.IsEnabled = _resultsPage > 0;
            NextPageButton.IsEnabled = (long)(_resultsPage + 1) * ResultsPageSize < page.TotalCount;
            BuildResultsGrid(displayedRows, criteria);
            SetStatus(ResultsTitleText.Text);
        }
        catch (Exception ex)
        {
            if (generation != _queryGeneration) return;
            BuildResultsGrid(Array.Empty<ResultPreviewRow>(), criteria);
            SetStatus($"Could not load results: {ex.Message}");
        }
        finally { if (generation == _queryGeneration) Mouse.OverrideCursor = null; }
    }

    private void ClearResults()
    {
        _queryGeneration++;
        Mouse.OverrideCursor = null;
        PreviousPageButton.IsEnabled = false;
        NextPageButton.IsEnabled = false;
        PageStatusText.Text = "0-0 of 0";
        _allRows.Clear();
        _caseRows.Clear();
        ResultsGrid.ItemsSource = null;
        ResultsGrid.Columns.Clear();
        ResultsGrid.SelectedItem = null;
        SetSelectedDetail(null);
        RegistryCountText.Text = "0";
        LocalCountText.Text = "0";
        _model.ClearArtifactCounts();
        _model.SelectArtifact(null);
        _selectedArtifactName = null;
        _selectedSystemProfileId = null;
        _selectedCategory=null;
        _model.SelectCategory(null);
        _caseArtifactCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        _caseSystemProfileCounts = new Dictionary<string, int>();
        ResultsTitleText.Text = UiText.Results;
        RunStateText.Text = UiText.Ready;
    }

    private static bool Contains(string value, string term)
    {
        return value?.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private void SetStatus(string text)
    {
        StatusTextBlock.Text = text;
    }

    private void ResultsGrid_SelectionChanged(object sender, GridSelectionChangedEventArgs e)
    {
        SetSelectedDetail(GetSelectedResultRow());
    }

    private void ResultsGrid_FilterChanged(object sender, GridFilterEventArgs e)
    {
        Dispatcher.BeginInvoke(new Action(UpdateNativeOverviewCounts));
    }

    private void UpdateNativeOverviewCounts()
    {
        if ((_selectedArtifactName != null && _selectedSystemProfileId == null) || ResultsGrid.View == null) return;
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var profileCounts = new Dictionary<string, int>();
        int total = 0;
        DataRowView? firstVisible = null;
        bool selectedVisible = false;
        foreach (var record in ResultsGrid.View.Records)
        {
            if (record.Data is not DataRowView view || view.Row[RowObjectColumn] is not ResultPreviewRow row) continue;
            firstVisible ??= view;
            if (ReferenceEquals(view, ResultsGrid.SelectedItem)) selectedVisible = true;
            counts[row.Artifact] = counts.GetValueOrDefault(row.Artifact) + 1;
            foreach(string profileId in row.SystemProfileViewIds)profileCounts[profileId]=profileCounts.GetValueOrDefault(profileId)+1;
            total++;
        }
        if (_selectedCategory!=null)
        {
            _model.UpdateArtifactCounts(_overviewArtifactCounts);
            _model.UpdateSystemProfileCounts(_overviewProfileCounts);
            foreach(var item in _selectedCategory.Items)
                item.HitCount=item.SystemProfileId==null?counts.GetValueOrDefault(item.Name):profileCounts.GetValueOrDefault(item.SystemProfileId);
            _selectedCategory.HitCount=total;
        }
        else if (_selectedSystemProfileId == null)
        {
            _model.UpdateArtifactCounts(counts);
            _model.UpdateSystemProfileCounts(profileCounts);
            AllArtifactsButton.Content = $"{UiText.AllArtifacts}: {total:N0} hits";
        }
        else _model.SetSystemProfileCount(_selectedSystemProfileId, total);
        string name = _selectedCategory?.Name ?? (_selectedSystemProfileId != null ? SystemProfileCatalog.Get(_selectedSystemProfileId).Name : _overviewSearchActive ? "Search results" : UiText.AllArtifacts);
        ResultsTitleText.Text = $"{name}: {total:N0} hits (of {_allRows.Count:N0})";
        if (!selectedVisible) ResultsGrid.SelectedItem = firstVisible;
        SetSelectedDetail(GetSelectedResultRow());
        SetStatus(ResultsTitleText.Text);
    }

    private void ResultsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        DependencyObject? source = e.OriginalSource as DependencyObject;
        if (FindVisualParent<GridCell>(source) is { } cell)
        {
            if (FindDataRowView(source) is { } rowView)
                SelectContextRow(rowView);
        }
    }

    private void SelectContextRow(DataRowView rowView)
    {
        if (ResultsGrid.SelectedItems.Contains(rowView)) return;
        ResultsGrid.SelectedItems.Clear();
        ResultsGrid.SelectedItem=rowView;
    }

    private DataRowView[] SelectedLabelViews()
    {
        var visible=ResultsGrid.View?.Records.Select(r=>r.Data).OfType<DataRowView>().ToHashSet()
            ?? new HashSet<DataRowView>();
        return ResultsGrid.SelectedItems.OfType<DataRowView>().Where(visible.Contains).ToArray();
    }

    private void ResultsContextMenu_Opened(object sender, RoutedEventArgs e)
    {
        BuildAddLabelMenu();
        CommentsMenuItem.IsEnabled=SelectedLabelViews().Length==1;
        CommentsMenuItem.ToolTip="Select one record to edit its comment.";
    }

    private void BuildAddLabelMenu()
    {
        AddLabelMenuItem.Items.Clear();
        var selection=SelectedLabelViews();
        AddLabelMenuItem.Header=selection.Length>1?$"Add label ({selection.Length:N0} selected)":"Add label";
        if (selection.Length==0 || string.IsNullOrWhiteSpace(_casePath))
        {
            AddLabelMenuItem.IsEnabled = false;
            return;
        }

        AddLabelMenuItem.IsEnabled = true;
        var currentLabels=selection.Select(v=>GetDetailValue((ResultPreviewRow)v.Row[RowObjectColumn],"Label")).ToArray();
        string currentLabel=currentLabels.Distinct(StringComparer.OrdinalIgnoreCase).Count()==1?currentLabels[0]:"";
        IReadOnlyList<LabelDefinition> labels = _caseReader.LoadLabels(_casePath);
        if (labels.Count == 0)
        {
            AddLabelMenuItem.Items.Add(new MenuItem
            {
                Header = "No labels available",
                IsEnabled = false
            });

        }

        foreach (LabelDefinition label in labels)
        {
            var item = new MenuItem
            {
                Header = label.Name,
                Icon = CreateLabelSwatch(label.Color),
                Tag = label.Name,
                IsCheckable = true,
                IsChecked = label.Name.Equals(currentLabel, StringComparison.OrdinalIgnoreCase),
                FontWeight = label.Name.Equals(currentLabel, StringComparison.OrdinalIgnoreCase)
                    ? FontWeights.SemiBold
                    : FontWeights.Normal
            };
            item.Click += AddLabelMenuItem_Click;
            AddLabelMenuItem.Items.Add(item);
        }

        if (currentLabels.Any(label=>!string.IsNullOrWhiteSpace(label)))
        {
            AddLabelMenuItem.Items.Add(new Separator());
            var clear = new MenuItem { Header = "Clear label", Tag = "" };
            clear.Click += AddLabelMenuItem_Click;
            AddLabelMenuItem.Items.Add(clear);
        }
    }

    private void AddLabelMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem item) SaveSelectedLabels(item.Tag?.ToString()??"");
    }

    private void SaveSelectedLabels(string label)
    {
        if (string.IsNullOrWhiteSpace(_casePath)) return;
        var views=SelectedLabelViews();
        if (views.Length==0) return;
        try
        {
            var rows=views.Select(v=>HydrateOverviewRow((ResultPreviewRow)v.Row[RowObjectColumn])).ToArray();
            int count=_caseReader.UpdateLabels(_casePath,rows.Select(r=>(r.TableName,r.RowId)).ToArray(),label);
            for(int i=0;i<rows.Length;i++)
            {
                var row=rows[i];
                var updated=row with {
                    DetailFields=ReplaceAnnotationFields(row.DetailFields,label.Trim(),GetDetailValue(row,"Comment")),
                    CommonFields=ReplaceAnnotationFields(row.CommonFields,label.Trim(),GetDetailValue(row,"Comment"))
                };
                ReplaceRowInMemory(row,updated);
                UpdateGridRow(views[i],updated);
            }
            ResultsGrid.View?.RefreshFilter(true);
            if (_selectedArtifactName==null || _selectedSystemProfileId!=null)
                Dispatcher.BeginInvoke(new Action(UpdateNativeOverviewCounts));
            SetSelectedDetail(GetSelectedResultRow());
            SetStatus($"Label {(string.IsNullOrWhiteSpace(label)?"cleared":"applied")} to {count:N0} selected records.");
        }
        catch(Exception ex)
        {
            SetStatus(UiText.AnnotationSaveError);
            WpfMessageBox.Show(this,ex.Message,"Prism",MessageBoxButton.OK,MessageBoxImage.Error);
        }
    }

    private void CommentsMenu_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedLabelViews().Length!=1) return;
        ResultPreviewRow? selected = GetSelectedResultRow();
        if (selected == null)
            return;

        var dialog = new CommentDialog(GetDetailValue(selected, "Comment")) { Owner = this };
        if (dialog.ShowDialog() == true)
            SaveAnnotation(selected, GetDetailValue(selected, "Label"), dialog.CommentText);
    }

    private void ManageLabelsMenu_Click(object sender, RoutedEventArgs e)
    {
        OpenLabelManager();
    }

    private void SaveAnnotation(ResultPreviewRow selected, string label, string comment)
    {
        if (string.IsNullOrWhiteSpace(_casePath))
            return;

        try
        {
            _caseReader.UpdateAnnotation(_casePath, selected.TableName, selected.RowId, label, comment);

            ResultPreviewRow updated = selected with
            {
                DetailFields = ReplaceAnnotationFields(selected.DetailFields, label.Trim(), comment.Trim()),
                CommonFields = ReplaceAnnotationFields(selected.CommonFields, label.Trim(), comment.Trim())
            };

            ReplaceRowInMemory(selected, updated);
            UpdateSelectedGridRow(updated);
            ResultsGrid.View?.RefreshFilter(true);
            if (_selectedArtifactName == null) Dispatcher.BeginInvoke(new Action(UpdateNativeOverviewCounts));
            SetSelectedDetail(updated);
            SetStatus(UiText.AnnotationSaved);
        }
        catch (Exception ex)
        {
            SetStatus(UiText.AnnotationSaveError);
            WpfMessageBox.Show(this, ex.Message, "Prism", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenLabelManager()
    {
        if (string.IsNullOrWhiteSpace(_casePath))
            return;

        var dialog = new LabelManagerDialog(_caseReader, _casePath) { Owner = this };
        dialog.ShowDialog();
        RefreshLabelCellStyles();
    }

    private void RefreshLabelCellStyles()
    {
        if (string.IsNullOrWhiteSpace(_casePath)) return;
        var colors=_caseReader.LoadLabels(_casePath).ToDictionary(l=>l.Name,l=>CreateLabelBrush(l.Color),StringComparer.OrdinalIgnoreCase);
        foreach(var column in ResultsGrid.Columns.Where(c=>c.MappingName=="Label"))
        {
            var style=new Style(typeof(GridCell));
            style.Setters.Add(new Setter(Control.BackgroundProperty,new Binding("Label") { Converter=new LabelCellBrushConverter(colors,false) }));
            style.Setters.Add(new Setter(Control.ForegroundProperty,new Binding("Label") { Converter=new LabelCellBrushConverter(colors,true) }));
            style.Setters.Add(new Setter(Control.FontWeightProperty,FontWeights.SemiBold));
            column.CellStyle=style;
        }
    }

    private static Border CreateLabelSwatch(string color)
    {
        return new Border
        {
            Width = 14,
            Height = 14,
            CornerRadius = new CornerRadius(3),
            BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
            BorderThickness = new Thickness(1),
            Background = CreateLabelBrush(color)
        };
    }

    private static Brush CreateLabelBrush(string color)
    {
        if (!string.IsNullOrWhiteSpace(color))
        {
            try
            {
                object? converted = ColorConverter.ConvertFromString(color.Trim());
                if (converted is Color parsed)
                    return new SolidColorBrush(parsed);
            }
            catch
            {
            }
        }

        return new SolidColorBrush(Color.FromRgb(203, 213, 225));
    }

    private void BuildResultsGrid(IReadOnlyList<ResultPreviewRow> rows, SearchCriteria? criteria = null)
    {
        ResultsGrid.Columns.Clear();
        bool overview = _selectedArtifactName == null;
        ResultsGrid.AllowSorting = overview || _selectedSystemProfileId != null || !(criteria?.IsActive ?? false);
        ResultsGrid.AllowFiltering = ResultsGrid.AllowSorting;

        var table = new DataTable();
        table.Columns.Add(RowObjectColumn, typeof(ResultPreviewRow));

        var columnNames = overview ? PrismCaseReader.CommonColumnNames : GetGridColumns(rows);
        if (!overview) columnNames = RecordFieldOrder(columnNames);
        foreach (string columnName in columnNames)
            table.Columns.Add(columnName, typeof(string));

        foreach (ResultPreviewRow row in rows)
        {
            System.Data.DataRow dataRow = table.NewRow();
            dataRow[RowObjectColumn] = row;
            foreach (ArtifactDetailField field in overview ? row.CommonFields : row.DetailFields)
                dataRow[field.Name] = field.Value;
            table.Rows.Add(dataRow);
        }

        foreach (System.Data.DataColumn column in table.Columns)
        {
            if (column.ColumnName == RowObjectColumn)
                continue;

            ResultsGrid.Columns.Add(new GridTextColumn
            {
                HeaderText = column.ColumnName,
                MappingName = column.ColumnName,
                Width = GetColumnWidth(column.ColumnName)
            });
        }

        RefreshLabelCellStyles();
        ResultsGrid.ItemsSource = table.DefaultView;
        if (rows.Count > 0)
            ResultsGrid.SelectedIndex = 0;
        else
            ResultsGrid.SelectedItem = null;

        SetSelectedDetail(rows.FirstOrDefault(), criteria ?? GetSearchCriteria());
    }

    private static IReadOnlyList<string> GetGridColumns(IReadOnlyList<ResultPreviewRow> rows)
    {
        var columns = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (ResultPreviewRow row in rows)
        {
            foreach (ArtifactDetailField field in row.DetailFields)
            {
                if (seen.Add(field.Name))
                    columns.Add(field.Name);
            }
        }

        return columns;
    }

    private static double GetColumnWidth(string columnName)
    {
        return columnName switch
        {
            "PropertyKey" => 220,
            "PropertyValue" => 340,
            "Potential activity" => 360,
            "Parsed hive path" => 420,
            "Parsed source file" => 420,
            "Source file" => 160,
            "Table" => 180,
            "Artifact type" => 170,
            "Label" => 140,
            "Comment" => 220,
            _ when columnName.Contains("time", StringComparison.OrdinalIgnoreCase) => 190,
            _ when columnName.Contains("path", StringComparison.OrdinalIgnoreCase) => 340,
            _ when columnName.Contains("name", StringComparison.OrdinalIgnoreCase) => 220,
            _ => 160
        };
    }

    private ResultPreviewRow? GetSelectedResultRow()
    {
        if (ResultsGrid.SelectedItem is DataRowView rowView &&
            rowView.Row.Table.Columns.Contains(RowObjectColumn) &&
            rowView.Row[RowObjectColumn] is ResultPreviewRow row)
        {
            var hydrated = HydrateOverviewRow(row);
            rowView.Row[RowObjectColumn] = hydrated;
            return hydrated;
        }

        return null;
    }

    private void SetSelectedDetail(ResultPreviewRow? row)
    {
        SetSelectedDetail(row, GetSearchCriteria());
    }

    private void SetSelectedDetail(ResultPreviewRow? row, SearchCriteria criteria)
    {
        if (row != null) row = HydrateOverviewRow(row);
        CopyDetailsButton.IsEnabled = row != null;
        if(row==null){_detailFields=Array.Empty<DetailDisplayField>();RenderDetails();return;}
        var fields=(row.CommonFields.Count>0&&_selectedArtifactName==null?OverviewDetails(row):row.DetailFields).ToArray();
        if(_selectedArtifactName!=null)
        {
            var ordered=RecordFieldOrder(fields.Select(field=>field.Name).ToArray());
            fields=ordered.Select(name=>fields.Single(field=>field.Name==name)).ToArray();
        }
        _detailFields=fields.Select(field=>BuildDetailDisplayField(field,criteria)).ToArray();
        RenderDetails();
    }

    private IReadOnlyList<DetailDisplayField> _detailFields = Array.Empty<DetailDisplayField>();

    private void RenderDetails()
    {
        var document=new FlowDocument{PagePadding=new Thickness(0),FontSize=FontSize};
        foreach(var field in _detailFields)
        {
            var paragraph=new Paragraph{Tag=field.Name,Margin=new Thickness(0,0,0,8),Padding=new Thickness(0,7,0,7),
                BorderBrush=new SolidColorBrush(Color.FromRgb(229,234,240)),BorderThickness=new Thickness(0,0,0,1)};
            paragraph.Inlines.Add(new Run(field.Name){FontSize=13,FontWeight=FontWeights.Bold,
                Foreground=new SolidColorBrush(Color.FromRgb(102,112,133))});
            paragraph.Inlines.Add(new LineBreak());
            foreach(var segment in field.Segments)
                paragraph.Inlines.Add(new Run(segment.Text){Background=segment.Background});
            document.Blocks.Add(paragraph);
        }
        DetailsBody.Document=document;
        DetailsBody.ScrollToHome();
    }

    private void ToggleDetails_Click(object sender,RoutedEventArgs e)
    {
        if(_detailsExpanded)
        {
            _expandedDetailsWidth=Math.Max(330,DetailsColumn.ActualWidth);
            DetailsBody.Visibility=Visibility.Collapsed;
            DetailsSplitter.Visibility=Visibility.Collapsed;
            DetailsColumn.MinWidth=0;
            DetailsColumn.Width=new GridLength(140);
            CopyDetailsButton.Visibility=Visibility.Collapsed;
            ToggleDetailsButton.Content=UiText.ShowDetails;
        }
        else
        {
            DetailsColumn.MinWidth=330;
            double available=Math.Max(330,MainWorkspace.ActualWidth-NavigationColumn.ActualWidth-ResultsColumn.MinWidth-12);
            DetailsColumn.Width=new GridLength(Math.Min(_expandedDetailsWidth,available));
            DetailsBody.Visibility=Visibility.Visible;
            DetailsSplitter.Visibility=Visibility.Visible;
            CopyDetailsButton.Visibility=Visibility.Visible;
            ToggleDetailsButton.Content=UiText.HideDetails;
        }
        _detailsExpanded=!_detailsExpanded;
    }

    private string DetailsAsText()=>string.Join(Environment.NewLine,_detailFields
        .Select(field=>field.Name+": "+string.Concat(field.Segments.Select(segment=>segment.Text))));

    private void CopyDetails_Click(object sender,RoutedEventArgs e)
    {
        if(!CopyDetailsButton.IsEnabled)return;
        try{Clipboard.SetText(DetailsAsText());SetStatus(UiText.DetailsCopied);}
        catch(Exception){SetStatus(UiText.DetailsCopyError);}
    }

    private static IReadOnlyList<string> RecordFieldOrder(IReadOnlyList<string> names)
    {
        var result=names.Where(name=>name is not ("Table" or "id")).ToList();
        int trailing=result.FindIndex(name=>name is "Parsed hive path" or "Parsed source file" or "Source file" or "Label" or "Comment");
        if(trailing<0)trailing=result.Count;
        result.InsertRange(trailing,names.Where(name=>name is "Table" or "id"));
        return result;
    }

    private ResultPreviewRow HydrateOverviewRow(ResultPreviewRow row)
    {
        if (row.DetailFields.Count > 0 || string.IsNullOrWhiteSpace(_casePath)) return row;
        var cached = _allRows.FirstOrDefault(r => r.TableName == row.TableName && r.RowId == row.RowId);
        if (cached?.DetailFields.Count > 0) return cached;
        try
        {
            var original = _caseReader.LoadOriginalRecord(_casePath, row, DisplayTime);
            if (original != null) { ReplaceRowInMemory(row, original); return original; }
            SetStatus("Original artifact record was not found.");
        }
        catch (Exception ex) { SetStatus($"Could not load original artifact details: {ex.Message}"); }
        return row;
    }

    private static IEnumerable<ArtifactDetailField> OverviewDetails(ResultPreviewRow row)
    {
        foreach (var field in row.CommonFields.Where(f => f.Name is not ("Label" or "Comment"))) yield return field;
        foreach (var field in row.DetailFields.Where(f => f.Name is not ("Label" or "Comment")))
        {
            var common = row.CommonFields.FirstOrDefault(f => f.Name == field.Name);
            if (common == null) yield return field;
            else if (common.Value != field.Value) yield return field with { Name = "Original " + field.Name };
        }
        foreach (var field in row.CommonFields.Where(f => f.Name is "Label" or "Comment")) yield return field;
    }

    private void ReplaceRowInMemory(ResultPreviewRow oldRow, ResultPreviewRow newRow)
    {
        int index = _allRows.FindIndex(row => row.TableName == oldRow.TableName && row.RowId == oldRow.RowId);
        if (index >= 0)
            _allRows[index] = newRow;

        int caseIndex = _caseRows.FindIndex(row => row.TableName == oldRow.TableName && row.RowId == oldRow.RowId);
        if (caseIndex >= 0)
            _caseRows[caseIndex] = newRow;
    }

    private void UpdateSelectedGridRow(ResultPreviewRow updated)
    {
        if (ResultsGrid.SelectedItem is not DataRowView rowView)
            return;

        UpdateGridRow(rowView,updated);
    }

    private static void UpdateGridRow(DataRowView rowView,ResultPreviewRow updated)
    {
        rowView.Row[RowObjectColumn] = updated;
        if (rowView.Row.Table.Columns.Contains("Label"))
            rowView.Row["Label"] = GetDetailValue(updated, "Label");
        if (rowView.Row.Table.Columns.Contains("Comment"))
            rowView.Row["Comment"] = GetDetailValue(updated, "Comment");
    }

    private static IReadOnlyList<ArtifactDetailField> ReplaceAnnotationFields(
        IReadOnlyList<ArtifactDetailField> fields,
        string label,
        string comment)
    {
        var updated = new List<ArtifactDetailField>(fields.Count + 2);
        bool sawLabel = false;
        bool sawComment = false;

        foreach (ArtifactDetailField field in fields)
        {
            if (field.Name.Equals("Label", StringComparison.OrdinalIgnoreCase))
            {
                updated.Add(field with { Value = label });
                sawLabel = true;
            }
            else if (field.Name.Equals("Comment", StringComparison.OrdinalIgnoreCase))
            {
                updated.Add(field with { Value = comment });
                sawComment = true;
            }
            else
            {
                updated.Add(field);
            }
        }

        if (!sawLabel)
            updated.Add(new ArtifactDetailField("Label", label));
        if (!sawComment)
            updated.Add(new ArtifactDetailField("Comment", comment));

        return updated;
    }

    private static string GetDetailValue(ResultPreviewRow? row, string name)
    {
        return row?.DetailFields.Concat(row.CommonFields).FirstOrDefault(
            field => field.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value ?? "";
    }

    private SearchCriteria GetSearchCriteria()
    {
        string term = SearchBox?.Text?.Trim() ?? "";
        Regex? regex = null;
        bool useRegex = RegexSearchCheckBox?.IsChecked == true;
        string? error = null;

        if (useRegex && !string.IsNullOrWhiteSpace(term))
        {
            try
            {
                regex = new Regex(term, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250));
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }

        bool useTime = TimeFilterCheckBox?.IsChecked == true;
        DateTimeOffset? from = null;
        DateTimeOffset? to = null;
        try
        {
            from = useTime ? DisplayTime.ParseBoundary(SearchFromBox?.Text) : null;
            to = useTime ? DisplayTime.ParseBoundary(SearchToBox?.Text, endOfDate: true) : null;
            if (from > to) error = "Start time must not be later than end time.";
        }
        catch (FormatException ex) { error = ex.Message; }

        return new SearchCriteria(
            term,
            useRegex,
            regex,
            from,
            to,
            LabelsFilterCheckBox?.IsChecked == true,
            error);
    }

    private bool MatchesSearch(ResultPreviewRow row, SearchCriteria criteria)
    {
        if (!string.IsNullOrWhiteSpace(criteria.RegexError))
            return false;

        if (criteria.HasLabel && string.IsNullOrWhiteSpace(GetDetailValue(row, "Label")))
            return false;

        if (criteria.From.HasValue || criteria.To.HasValue)
        {
            if (!TryGetRowTimestamp(row, out DateTimeOffset timestamp))
                return false;

            if (criteria.From.HasValue && timestamp < criteria.From.Value)
                return false;
            if (criteria.To.HasValue && timestamp > criteria.To.Value)
                return false;
        }

        if (string.IsNullOrWhiteSpace(criteria.Term))
            return true;

        return GetSearchableValues(row).Any(value => MatchesText(value, criteria));
    }

    private static IEnumerable<string> GetSearchableValues(ResultPreviewRow row)
    {
        yield return row.Artifact;
        yield return row.Activity;
        yield return row.Name;
        yield return row.Source;
        yield return row.Timestamp;

        foreach (ArtifactDetailField field in row.CommonFields.Concat(row.DetailFields))
        {
            yield return field.Name;
            yield return field.Value;
        }
    }

    private static bool MatchesText(string value, SearchCriteria criteria)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        if (criteria.Regex != null)
            return criteria.Regex.IsMatch(value);

        return value.IndexOf(criteria.Term, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static DetailDisplayField BuildDetailDisplayField(ArtifactDetailField field, SearchCriteria criteria)
    {
        return new DetailDisplayField(field.Name, BuildSegments(field.Value, criteria));
    }

    private static IReadOnlyList<DetailTextSegment> BuildSegments(string value, SearchCriteria criteria)
    {
        if (string.IsNullOrEmpty(value) || string.IsNullOrWhiteSpace(criteria.Term) || !string.IsNullOrWhiteSpace(criteria.RegexError))
            return new[] { new DetailTextSegment(value, Brushes.Transparent) };

        var segments = new List<DetailTextSegment>();
        try
        {
            MatchCollection matches = criteria.Regex != null
                ? criteria.Regex.Matches(value)
                : Regex.Matches(value, Regex.Escape(criteria.Term), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            int index = 0;
            foreach (Match match in matches.Cast<Match>().Where(match => match.Success && match.Length > 0))
            {
                if (match.Index > index)
                    segments.Add(new DetailTextSegment(value[index..match.Index], Brushes.Transparent));

                segments.Add(new DetailTextSegment(value.Substring(match.Index, match.Length), Brushes.Gold));
                index = match.Index + match.Length;
            }

            if (index < value.Length)
                segments.Add(new DetailTextSegment(value[index..], Brushes.Transparent));
        }
        catch
        {
            return new[] { new DetailTextSegment(value, Brushes.Transparent) };
        }

        return segments.Count > 0 ? segments : new[] { new DetailTextSegment(value, Brushes.Transparent) };
    }

    private static bool TryGetRowTimestamp(ResultPreviewRow row, out DateTimeOffset timestamp)
    {
        timestamp = row.TimestampUtc ?? default;
        return row.TimestampUtc.HasValue;
    }
    private static T? FindVisualParent<T>(DependencyObject? source)
        where T : DependencyObject
    {
        while (source != null)
        {
            if (source is T match)
                return match;

            source = VisualTreeHelper.GetParent(source);
        }

        return null;
    }

    private static DataRowView? FindDataRowView(DependencyObject? source)
    {
        while (source != null)
        {
            if (source is FrameworkElement { DataContext: DataRowView rowView })
                return rowView;

            source = VisualTreeHelper.GetParent(source);
        }

        return null;
    }

    private static string Tail(string value, int maxChars)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxChars)
            return value;
        return value[^maxChars..];
    }
}

internal sealed class ShellDesignModel
{
    public ObservableCollection<ArtifactNavGroup> ArtifactGroups { get; init; } = new();

    public int RegistryArtifactCount => ArtifactGroups
        .SelectMany(group => group.Items)
        .Count(item => item.Source is "Registry");

    public int LocalArtifactCount => ArtifactGroups
        .SelectMany(group => group.Items)
        .Count(item => item.Source is "File");

    public string StatusText { get; init; } = "";

    public static ShellDesignModel Create()
    {
        return new ShellDesignModel
        {
            ArtifactGroups = new ObservableCollection<ArtifactNavGroup>(
                new[]{new ArtifactNavGroup(SystemProfileCatalog.GroupName,new ObservableCollection<ArtifactNavItem>(
                    SystemProfileCatalog.Views.Select(view=>new ArtifactNavItem(view.Name,"Profile",view.Id,view.Description))))}
                .Concat(ArtifactCatalog.Groups.Select(group => new ArtifactNavGroup(
                    group.Name,
                    new ObservableCollection<ArtifactNavItem>(
                        group.Items.Select(item => new ArtifactNavItem(item.Name, item.Source))))))),
            StatusText = UiText.ReadyWithPeriod
        };
    }

    public void UpdateArtifactCounts(IReadOnlyDictionary<string, int> counts)
    {
        foreach (ArtifactNavItem item in ArtifactGroups.SelectMany(group => group.Items))
        {
            if(item.SystemProfileId != null)continue;
            item.HitCount = counts.TryGetValue(item.Name, out int count) ? count : 0;
        }
        foreach(var group in ArtifactGroups)
            group.HitCount=group.Items.Select(item=>item.SystemProfileId==null?item.Name:SystemProfileCatalog.Get(item.SystemProfileId).ArtifactName)
                .Distinct(StringComparer.OrdinalIgnoreCase).Sum(name=>counts.GetValueOrDefault(name));
    }

    public void UpdateSystemProfileCounts(IReadOnlyDictionary<string,int> counts)
    {
        foreach(var item in ArtifactGroups.SelectMany(group=>group.Items).Where(item=>item.SystemProfileId!=null))
            item.HitCount=counts.GetValueOrDefault(item.SystemProfileId!);
    }
    public void SetSystemProfileCount(string id,int count)
    {
        foreach(var item in ArtifactGroups.SelectMany(group=>group.Items).Where(item=>item.SystemProfileId==id))item.HitCount=count;
    }

    public void ClearArtifactCounts()
    {
        foreach (ArtifactNavItem item in ArtifactGroups.SelectMany(group => group.Items))
            item.HitCount = 0;
        foreach(var group in ArtifactGroups)group.HitCount=0;
    }

    public void SelectCategory(ArtifactNavGroup? selected)
    {
        foreach(var group in ArtifactGroups)group.IsSelected=ReferenceEquals(group,selected);
    }

    public void SelectArtifact(ArtifactNavItem? selected)
    {
        foreach (ArtifactNavItem item in ArtifactGroups.SelectMany(group => group.Items))
            item.IsSelected = ReferenceEquals(item, selected);
    }
}

internal sealed class ArtifactNavGroup(string name,ObservableCollection<ArtifactNavItem> items) : INotifyPropertyChanged
{
    public string Name {get;}=name;
    public ObservableCollection<ArtifactNavItem> Items {get;}=items;
    private bool _isSelected;
    private int _hitCount;
    public bool IsSelected {get=>_isSelected;set{_isSelected=value;PropertyChanged?.Invoke(this,new(nameof(IsSelected)));}}
    public int HitCount {get=>_hitCount;set{_hitCount=value;PropertyChanged?.Invoke(this,new(nameof(HitCount)));PropertyChanged?.Invoke(this,new(nameof(CountText)));}}
    public string CountText=>$"{HitCount:N0} hits";
    public bool Contains(ResultPreviewRow row)=>Items.Any(item=>item.SystemProfileId==null
        ?item.Name.Equals(row.Artifact,StringComparison.OrdinalIgnoreCase)
        :row.SystemProfileViewIds.Contains(item.SystemProfileId));
    public event PropertyChangedEventHandler? PropertyChanged;
}

internal sealed record EvidenceTimeZoneChoice(string DisplayName, TimeZoneInfo Zone)
{
    public static EvidenceTimeZoneChoice Utc { get; } = new("(UTC) Coordinated Universal Time", TimeZoneInfo.Utc);

    public override string ToString() => DisplayName;

    public static IReadOnlyList<EvidenceTimeZoneChoice> BuildChoices() => TimeZoneInfo.GetSystemTimeZones()
        .Select(zone=>zone.Id=="UTC"?Utc:new EvidenceTimeZoneChoice(zone.DisplayName,
            TimeZoneInfo.CreateCustomTimeZone(zone.Id,zone.BaseUtcOffset,zone.DisplayName,zone.StandardName)))
        .OrderBy(choice=>choice.Zone.BaseUtcOffset).ThenBy(choice=>choice.DisplayName,StringComparer.CurrentCulture)
        .ToArray();

    internal static string FormatOffset(TimeSpan offset)
    {
        if(offset==TimeSpan.Zero)return "UTC";
        string sign=offset<TimeSpan.Zero?"-":"+";
        offset=offset.Duration();
        return $"UTC{sign}{offset.Hours:00}:{offset.Minutes:00}";
    }
}

internal sealed record SearchCriteria(
    string Term,
    bool UseRegex,
    Regex? Regex,
    DateTimeOffset? From,
    DateTimeOffset? To,
    bool HasLabel,
    string? RegexError)
{
    public bool IsActive =>
        !string.IsNullOrWhiteSpace(Term) ||
        From.HasValue ||
        To.HasValue ||
        HasLabel ||
        !string.IsNullOrWhiteSpace(RegexError);
}

internal sealed record DetailDisplayField(string Name, IReadOnlyList<DetailTextSegment> Segments);

internal sealed record DetailTextSegment(string Text, Brush Background);

internal sealed class ArtifactNavItem : INotifyPropertyChanged
{
    private int _hitCount;
    private bool _isSelected;

    public ArtifactNavItem(string name, string source, string? systemProfileId=null, string? description=null)
    {
        Name = name;
        Source = source;
        SystemProfileId = systemProfileId;
        Description = description ?? name;
    }

    public string Name { get; }

    public string Source { get; }
    public string? SystemProfileId { get; }
    public string Description { get; }

    public int HitCount
    {
        get => _hitCount;
        set
        {
            if (_hitCount == value)
                return;

            _hitCount = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CountText));
        }
    }

    public string CountText => $"{HitCount:N0} hits";

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value)
                return;

            _isSelected = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

internal enum StartAction
{
    None,
    NewCaseAndScan,
    E01,
    OfflineFolder,
    LiveMachine,
    OpenCase,
    Exit,
    AD1
}

internal sealed class LabelAssignmentDialog : Window
{
    private readonly Func<IReadOnlyList<LabelDefinition>> _loadLabels;
    private readonly ComboBox _labelBox = new() { IsEditable = true, MinHeight = 30 };

    public LabelAssignmentDialog(
        Func<IReadOnlyList<LabelDefinition>> loadLabels,
        string label,
        Action manageLabels)
    {
        _loadLabels = loadLabels;
        FontSize = App.DefaultFontSize;
        Title = UiText.EditLabels;
        Width = 430;
        Height = 190;
        MinWidth = 430;
        MinHeight = 190;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Brushes.White;

        var root = new Grid { Margin = new Thickness(14) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        root.Children.Add(new TextBlock
        {
            Text = UiText.Label,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.Black
        });

        var labelRow = new Grid { Margin = new Thickness(0, 6, 0, 12) };
        labelRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        labelRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _labelBox.Text = label;
        labelRow.Children.Add(_labelBox);

        var manageButton = new Button
        {
            Content = UiText.ManageLabels,
            Margin = new Thickness(8, 0, 0, 0),
            MinWidth = 115
        };
        manageButton.Click += (_, _) =>
        {
            manageLabels();
            LoadLabels();
        };
        Grid.SetColumn(manageButton, 1);
        labelRow.Children.Add(manageButton);
        Grid.SetRow(labelRow, 1);
        root.Children.Add(labelRow);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0)
        };
        var cancel = new Button { Content = "Cancel", MinWidth = 85, Margin = new Thickness(0, 0, 8, 0) };
        cancel.Click += (_, _) => Close();
        var save = new Button { Content = "Save", MinWidth = 85 };
        save.Click += (_, _) => DialogResult = true;
        buttons.Children.Add(cancel);
        buttons.Children.Add(save);
        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        Content = root;
        LoadLabels();
    }

    public string LabelText => _labelBox.Text ?? "";

    private void LoadLabels()
    {
        string current = _labelBox.Text;
        _labelBox.ItemsSource = _loadLabels().Select(label => label.Name).ToArray();
        _labelBox.Text = current;
    }
}

internal sealed class CommentDialog : Window
{
    private readonly TextBox _commentBox = new()
    {
        MinHeight = 140,
        AcceptsReturn = true,
        TextWrapping = TextWrapping.Wrap,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto
    };

    public CommentDialog(string comment)
    {
        FontSize = App.DefaultFontSize;
        Title = UiText.EditComment;
        Width = 460;
        Height = 280;
        MinWidth = 460;
        MinHeight = 280;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Brushes.White;

        var root = new Grid { Margin = new Thickness(14) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        root.Children.Add(new TextBlock
        {
            Text = UiText.Comment,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.Black
        });

        _commentBox.Text = comment;
        _commentBox.Margin = new Thickness(0, 6, 0, 0);
        Grid.SetRow(_commentBox, 1);
        root.Children.Add(_commentBox);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0)
        };
        var cancel = new Button { Content = "Cancel", MinWidth = 85, Margin = new Thickness(0, 0, 8, 0) };
        cancel.Click += (_, _) => Close();
        var save = new Button { Content = "Save", MinWidth = 85 };
        save.Click += (_, _) => DialogResult = true;
        buttons.Children.Add(cancel);
        buttons.Children.Add(save);
        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        Content = root;
    }

    public string CommentText => _commentBox.Text ?? "";
}

internal sealed class LabelManagerDialog : Window
{
    private readonly PrismCaseReader _caseReader;
    private readonly string _casePath;
    private readonly ListBox _labelsList = new();
    private readonly TextBox _nameBox = new();
    private readonly TextBox _descriptionBox = new();
    private readonly TextBlock _countText = new();
    private readonly List<Button> _paletteButtons = new();
    private Color _selectedColor = Color.FromRgb(31, 92, 143);
    private readonly Border _colorPreview = new()
    {
        Width = 58,
        Height = 58,
        CornerRadius = new CornerRadius(6),
        BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
        BorderThickness = new Thickness(1),
        Background = new SolidColorBrush(Color.FromRgb(31, 92, 143)),
        Margin = new Thickness(0, 0, 12, 0)
    };
    private static readonly Color[] LabelPalette =
    {
        Color.FromRgb(31, 92, 143),
        Color.FromRgb(14, 116, 144),
        Color.FromRgb(22, 163, 74),
        Color.FromRgb(132, 204, 22),
        Color.FromRgb(234, 179, 8),
        Color.FromRgb(249, 115, 22),
        Color.FromRgb(220, 38, 38),
        Color.FromRgb(190, 24, 93),
        Color.FromRgb(124, 58, 237),
        Color.FromRgb(79, 70, 229),
        Color.FromRgb(8, 145, 178),
        Color.FromRgb(75, 85, 99),
        Color.FromRgb(15, 23, 42),
        Color.FromRgb(120, 113, 108),
        Color.FromRgb(100, 116, 139),
        Color.FromRgb(217, 119, 6)
    };

    public LabelManagerDialog(PrismCaseReader caseReader, string casePath)
    {
        FontSize = App.DefaultFontSize;
        _caseReader = caseReader;
        _casePath = casePath;
        Title = UiText.ManageLabels;
        Width = 760;
        Height = 560;
        MinWidth = 720;
        MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(244, 246, 248));

        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = new Border
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(216, 222, 230)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(18, 14, 18, 12),
            Child = new StackPanel
            {
                Children =
                {
                    new TextBlock
                    {
                        Text = "Case labels",
                        FontSize = 18,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = Brushes.Black
                    },
                    new TextBlock
                    {
                        Text = "Create reusable labels for forensic review and assign a visual color for quick triage.",
                        Foreground = new SolidColorBrush(Color.FromRgb(71, 85, 105)),
                        Margin = new Thickness(0, 3, 0, 0)
                    }
                }
            }
        };
        root.Children.Add(header);

        var body = new Grid { Margin = new Thickness(14) };
        body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(255) });
        body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(body, 1);
        root.Children.Add(body);

        var leftBorder = new Border
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(216, 222, 230)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(10)
        };
        body.Children.Add(leftBorder);

        var left = new DockPanel();
        leftBorder.Child = left;

        _countText.Foreground = Brushes.DimGray;
        _countText.Margin = new Thickness(0, 8, 0, 0);
        DockPanel.SetDock(_countText, Dock.Bottom);
        left.Children.Add(_countText);

        _labelsList.ItemTemplate = BuildLabelItemTemplate();
        _labelsList.SelectionChanged += (_, _) => PopulateSelectedLabel();
        left.Children.Add(_labelsList);

        var editorBorder = new Border
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(216, 222, 230)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(14),
            Margin = new Thickness(12, 0, 0, 0)
        };
        Grid.SetColumn(editorBorder, 1);
        body.Children.Add(editorBorder);

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };
        editorBorder.Child = scroll;

        var form = new Grid();
        for (int i = 0; i < 6; i++)
            form.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        scroll.Content = form;

        AddFormField(form, UiText.Label, _nameBox, 0);
        AddFormField(form, "Description", _descriptionBox, 2, multiline: true);
        AddColorField(form, 4);

        var footer = new Border
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(216, 222, 230)),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(14, 10, 14, 10)
        };
        Grid.SetRow(footer, 2);
        root.Children.Add(footer);

        var footerGrid = new Grid();
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        footer.Child = footerGrid;

        var leftActions = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        footerGrid.Children.Add(leftActions);

        var addNew = CreateDialogButton("New", primary: false);
        addNew.Margin = new Thickness(0, 0, 8, 0);
        addNew.Click += (_, _) => ClearEditor();
        var delete = CreateDialogButton("Delete", primary: false);
        delete.Click += (_, _) => DeleteCurrentLabel();
        leftActions.Children.Add(addNew);
        leftActions.Children.Add(delete);

        var rightActions = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        Grid.SetColumn(rightActions, 1);
        footerGrid.Children.Add(rightActions);

        var save = CreateDialogButton("Save", primary: true);
        save.IsEnabled = !string.IsNullOrWhiteSpace(_nameBox.Text);
        _nameBox.TextChanged += (_, _) => save.IsEnabled = !string.IsNullOrWhiteSpace(_nameBox.Text);
        save.Margin = new Thickness(0, 0, 8, 0);
        save.Click += (_, _) => SaveCurrentLabel();
        var close = CreateDialogButton("Close", primary: false);
        close.Click += (_, _) => Close();
        rightActions.Children.Add(save);
        rightActions.Children.Add(close);

        Content = root;
        LoadLabels();
    }

    private static Button CreateDialogButton(string text, bool primary)
    {
        var color = Color.FromRgb(31, 92, 143);
        return new Button
        {
            Content = text,
            MinWidth = 92,
            MinHeight = 34,
            Padding = new Thickness(14, 5, 14, 5),
            Background = primary ? new SolidColorBrush(color) : Brushes.White,
            BorderBrush = primary ? new SolidColorBrush(color) : new SolidColorBrush(Color.FromRgb(203, 213, 225)),
            Foreground = primary ? Brushes.White : new SolidColorBrush(Color.FromRgb(31, 41, 55)),
            FontWeight = primary ? FontWeights.SemiBold : FontWeights.Normal
        };
    }

    private static void AddFormField(Grid form, string label, TextBox textBox, int row, bool multiline = false)
    {
        var text = new TextBlock
        {
            Text = label,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, row == 0 ? 0 : 10, 0, 5)
        };
        Grid.SetRow(text, row);
        form.Children.Add(text);

        textBox.MinHeight = 30;
        textBox.VerticalContentAlignment = multiline ? VerticalAlignment.Top : VerticalAlignment.Center;
        textBox.Padding = multiline ? new Thickness(7) : new Thickness(7, 0, 7, 0);
        textBox.AcceptsReturn = multiline;
        textBox.TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap;
        if (multiline)
        {
            textBox.MinHeight = 80;
            textBox.MaxHeight = 120;
            textBox.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
        }
        Grid.SetRow(textBox, row + 1);
        form.Children.Add(textBox);
    }

    private static DataTemplate BuildLabelItemTemplate()
    {
        var root = new FrameworkElementFactory(typeof(DockPanel));
        root.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 3, 0, 3));
        root.SetValue(FrameworkElement.MinHeightProperty, 38.0);

        var swatch = new FrameworkElementFactory(typeof(Border));
        swatch.SetValue(FrameworkElement.WidthProperty, 18.0);
        swatch.SetValue(FrameworkElement.HeightProperty, 18.0);
        swatch.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
        swatch.SetValue(Border.BorderThicknessProperty, new Thickness(1));
        swatch.SetValue(Border.BorderBrushProperty, new SolidColorBrush(Color.FromRgb(203, 213, 225)));
        swatch.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 0, 9, 0));
        swatch.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        swatch.SetValue(DockPanel.DockProperty, Dock.Left);
        swatch.SetBinding(Border.BackgroundProperty, new Binding(nameof(LabelDefinition.Color)) { Converter = new LabelColorBrushConverter() });
        root.AppendChild(swatch);

        var textStack = new FrameworkElementFactory(typeof(StackPanel));
        var name = new FrameworkElementFactory(typeof(TextBlock));
        name.SetBinding(TextBlock.TextProperty, new Binding(nameof(LabelDefinition.Name)));
        name.SetValue(TextBlock.FontWeightProperty, FontWeights.SemiBold);
        name.SetValue(TextBlock.ForegroundProperty, Brushes.Black);
        textStack.AppendChild(name);

        var description = new FrameworkElementFactory(typeof(TextBlock));
        description.SetBinding(TextBlock.TextProperty, new Binding(nameof(LabelDefinition.Description)));
        description.SetValue(TextBlock.ForegroundProperty, Brushes.DimGray);
        description.SetValue(TextBlock.FontSizeProperty, 13.0);
        description.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
        textStack.AppendChild(description);

        root.AppendChild(textStack);
        return new DataTemplate { VisualTree = root };
    }

    private void AddColorField(Grid form, int row)
    {
        var text = new TextBlock
        {
            Text = "Color",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 10, 0, 5)
        };
        Grid.SetRow(text, row);
        form.Children.Add(text);

        var colorPanel = new Grid();
        colorPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        colorPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        colorPanel.Children.Add(_colorPreview);

        var right = new StackPanel();
        Grid.SetColumn(right, 1);
        colorPanel.Children.Add(right);


        var palette = new UniformGrid { Columns = 8, Rows = 2, Margin = new Thickness(0, 0, 0, 10) };
        foreach (Color color in LabelPalette)
        {
            var swatch = new Button
            {
                Width = 24,
                Height = 24,
                MinHeight = 24,
                Padding = new Thickness(0),
                Margin = new Thickness(0, 0, 6, 6),
                Background = new SolidColorBrush(color),
                BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
                BorderThickness = new Thickness(1),
                Tag = color,
                ToolTip = "Use this color"
            };
            swatch.Click += (_, _) => SetSelectedColor((Color)swatch.Tag);
            _paletteButtons.Add(swatch);
            palette.Children.Add(swatch);
        }
        right.Children.Add(palette);

        var choose = new Button
        {
            Content = "Custom color...",
            MinWidth = 120,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        choose.Click += (_, _) => ChooseColor();
        right.Children.Add(choose);

        Grid.SetRow(colorPanel, row + 1);
        form.Children.Add(colorPanel);
        SetSelectedColor(_selectedColor);
    }

    private void ChooseColor()
    {
        if (NativeColorDialog.TryShow(this, _selectedColor, out Color selected))
            SetSelectedColor(selected);
    }

    private void LoadLabels()
    {
        IReadOnlyList<LabelDefinition> labels = _caseReader.LoadLabels(_casePath);
        _labelsList.ItemsSource = labels;
        _countText.Text = $"{labels.Count:N0} labels";
    }

    private void PopulateSelectedLabel()
    {
        if (_labelsList.SelectedItem is not LabelDefinition label)
            return;

        _nameBox.Text = label.Name;
        _descriptionBox.Text = label.Description;
        SetSelectedColor(TryParseColor(label.Color, out Color color) ? color : LabelPalette[0]);
    }

    private void SaveCurrentLabel()
    {
        if (string.IsNullOrWhiteSpace(_nameBox.Text))
        {
            _nameBox.Focus();
            return;
        }

        _caseReader.SaveLabel(_casePath, _nameBox.Text, _descriptionBox.Text, FormatColor(_selectedColor));
        LoadLabels();
        SelectLabel(_nameBox.Text);
    }

    private void DeleteCurrentLabel()
    {
        if (_labelsList.SelectedItem is not LabelDefinition label)
            return;

        MessageBoxResult answer = WpfMessageBox.Show(
            this,
            $"Delete label '{label.Name}' and remove it from annotated artifacts?",
            "Prism",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes)
            return;

        _caseReader.DeleteLabel(_casePath, label.Name);
        ClearEditor();
        LoadLabels();
    }

    private void ClearEditor()
    {
        _labelsList.SelectedItem = null;
        _nameBox.Clear();
        _descriptionBox.Clear();
        SetSelectedColor(LabelPalette[0]);
        _nameBox.Focus();
    }

    private void SelectLabel(string name)
    {
        foreach (object item in _labelsList.Items)
        {
            if (item is LabelDefinition label && label.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                _labelsList.SelectedItem = item;
                break;
            }
        }
    }

    private void SetSelectedColor(Color color)
    {
        _selectedColor = color;
        _colorPreview.Background = new SolidColorBrush(color);

        foreach (Button button in _paletteButtons)
        {
            bool selected = button.Tag is Color paletteColor && paletteColor == color;
            button.BorderBrush = selected
                ? new SolidColorBrush(Color.FromRgb(17, 24, 39))
                : new SolidColorBrush(Color.FromRgb(203, 213, 225));
            button.BorderThickness = selected ? new Thickness(2) : new Thickness(1);
        }
    }

    private static string FormatColor(Color color) => $"#{color.R:X2}{color.G:X2}{color.B:X2}";

    private static bool TryParseColor(string value, out Color color)
    {
        color = Colors.Transparent;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        try
        {
            object? converted = ColorConverter.ConvertFromString(value.Trim());
            if (converted is Color parsed)
            {
                color = parsed;
                return true;
            }
        }
        catch
        {
        }

        return false;
    }
}

internal sealed class LabelColorBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string text && !string.IsNullOrWhiteSpace(text))
        {
            try
            {
                object? converted = ColorConverter.ConvertFromString(text.Trim());
                if (converted is Color color)
                    return new SolidColorBrush(color);
            }
            catch
            {
            }
        }

        return new SolidColorBrush(Color.FromRgb(203, 213, 225));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

internal static class NativeColorDialog
{
    private const int CcRgbInit = 0x00000001;
    private const int CcFullOpen = 0x00000002;

    public static bool TryShow(Window owner, Color initialColor, out Color selectedColor)
    {
        selectedColor = initialColor;
        IntPtr customColors = Marshal.AllocHGlobal(sizeof(int) * 16);

        try
        {
            for (int i = 0; i < 16; i++)
                Marshal.WriteInt32(customColors, i * sizeof(int), 0x00FFFFFF);

            var data = new ChooseColorData
            {
                lStructSize = Marshal.SizeOf<ChooseColorData>(),
                hwndOwner = new WindowInteropHelper(owner).Handle,
                rgbResult = ToColorRef(initialColor),
                lpCustColors = customColors,
                Flags = CcRgbInit | CcFullOpen
            };

            if (!ChooseColor(ref data))
                return false;

            selectedColor = FromColorRef(data.rgbResult);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(customColors);
        }
    }

    private static int ToColorRef(Color color) => color.R | (color.G << 8) | (color.B << 16);

    private static Color FromColorRef(int colorRef) =>
        Color.FromRgb(
            (byte)(colorRef & 0xFF),
            (byte)((colorRef >> 8) & 0xFF),
            (byte)((colorRef >> 16) & 0xFF));

    [DllImport("comdlg32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChooseColor(ref ChooseColorData chooseColor);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct ChooseColorData
    {
        public int lStructSize;
        public IntPtr hwndOwner;
        public IntPtr hInstance;
        public int rgbResult;
        public IntPtr lpCustColors;
        public int Flags;
        public IntPtr lCustData;
        public IntPtr lpfnHook;
        public IntPtr lpTemplateName;
    }
}

internal sealed class StartDialog : Window
{
    public StartAction Selection { get; private set; }

    public StartDialog()
    {
        FontSize = App.DefaultFontSize;
        Title = "Prism";
        Width = 600;
        Height = 470;
        MinWidth = 600;
        MinHeight = 470;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(246, 248, 251));

        var root = new Grid { Margin = new Thickness(38, 34, 38, 28) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var hero = new Grid();
        hero.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        hero.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var logo = new Image
        {
            Width = 40,
            Height = 40,
            VerticalAlignment = VerticalAlignment.Top,
            Source = new System.Windows.Media.Imaging.BitmapImage(
                new Uri("pack://application:,,,/Prism;component/Assets/prism.png"))
        };
        hero.Children.Add(logo);

        var titleStack = new StackPanel { Margin = new Thickness(18, 0, 0, 0) };
        titleStack.Children.Add(new TextBlock
        {
            Text = "Prism",
            FontSize = 26,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.Black
        });
        titleStack.Children.Add(new TextBlock
        {
            Text = "Start a new Windows forensic artifact review or continue with an existing .pri case.",
            Foreground = new SolidColorBrush(Color.FromRgb(51, 65, 85)),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 7, 0, 0),
            MaxWidth = 430
        });
        Grid.SetColumn(titleStack, 1);
        hero.Children.Add(titleStack);
        root.Children.Add(hero);

        var question = new TextBlock
        {
            Text = "What do you want to do?",
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.Black,
            Margin = new Thickness(4, 36, 0, 12)
        };
        Grid.SetRow(question, 1);
        root.Children.Add(question);

        var actions = new StackPanel { Margin = new Thickness(0, 0, 0, 18) };
        actions.Children.Add(ActionButton("New Case", "", StartAction.NewCaseAndScan));
        actions.Children.Add(ActionButton("Open Case", "", StartAction.OpenCase));
        actions.Children.Add(ActionButton("Close Prism.", "", StartAction.Exit, closeWindow: true));
        Grid.SetRow(actions, 2);
        root.Children.Add(actions);

        var footer = new TextBlock
        {
            Text = "Windows artifacts review workflow",
            Foreground = new SolidColorBrush(Color.FromRgb(100, 116, 139)),
            HorizontalAlignment = HorizontalAlignment.Right
        };
        Grid.SetRow(footer, 3);
        root.Children.Add(footer);

        Content = root;
    }

    private Button ActionButton(string title, string description, StartAction action, bool closeWindow = false)
    {
        var button = new Button
        {
            Margin = new Thickness(0, 0, 0, 10),
            MinHeight = 52,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(24, 8, 18, 8),
            BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
            BorderThickness = new Thickness(1),
            Background = Brushes.White,
            Content = new StackPanel
            {
                Children =
                {
                    new TextBlock { Text = title, Foreground = Brushes.Black, FontSize = 16 },
                    new TextBlock { Text = description, Foreground = Brushes.Black, FontSize = 14, Margin = new Thickness(0, 2, 0, 0) }
                }
            }
        };
        button.Click += (_, _) =>
        {
            if (closeWindow)
            {
                Selection = action;
                DialogResult = true;
                return;
            }

            Selection = action;
            DialogResult = true;
        };
        return button;
    }
}

internal sealed class SourceChoiceDialog : Window
{
    public StartAction Selection { get; private set; }

    public SourceChoiceDialog()
    {
        FontSize = App.DefaultFontSize;
        Title = "Select evidence";
        Width = 430;
        Height = 330;
        MinWidth = 430;
        MinHeight = 330;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Brushes.White;

        var root = new Grid { Margin = new Thickness(18) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        root.Children.Add(new TextBlock
        {
            Text = "Choose evidence source",
            FontSize = 18,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.Black
        });

        var buttons = new UniformGrid { Rows = 4, Columns = 1, Margin = new Thickness(0, 18, 0, 0) };
        buttons.Children.Add(ActionButton(UiText.ScanE01, StartAction.E01));
        buttons.Children.Add(ActionButton(UiText.ScanAd1, StartAction.AD1));
        buttons.Children.Add(ActionButton(UiText.ScanFolder, StartAction.OfflineFolder));
        buttons.Children.Add(ActionButton(UiText.ScanLiveSystem, StartAction.LiveMachine));
        Grid.SetRow(buttons, 1);
        root.Children.Add(buttons);

        Content = root;
    }

    private Button ActionButton(string text, StartAction action)
    {
        var button = new Button
        {
            Content = text,
            Margin = new Thickness(0, 0, 0, 8),
            MinHeight = 42,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(14, 0, 14, 0)
        };
        button.Click += (_, _) =>
        {
            Selection = action;
            DialogResult = true;
        };
        return button;
    }
}
