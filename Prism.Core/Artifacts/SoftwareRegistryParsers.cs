using Registry;
using System.Data.SQLite;
using System.Text.RegularExpressions;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record NetworkListParseResult(int Inserted);

public sealed record InstalledProgramsParseResult(int Inserted);

public sealed record AutorunParseResult(int Inserted);

public sealed record UserProfilesParseResult(int Inserted);

public sealed record WindowsUpdatesParseResult(int Inserted);

public sealed record DefenderExclusionsParseResult(int Inserted);

public sealed record SoftwareSystemInfoParseResult(int Inserted);

public static class SoftwareRegistryParsers
{
    public static void CreateTables(SQLiteConnection connection)
    {
        using var networkList = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS networklist_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            ProfileName TEXT,
            Description TEXT,
            SSID TEXT,
            DnsSuffix TEXT,
            DefaultGatewayMac TEXT,
            FirstConnect TEXT,
            LastConnect TEXT,
            NetworkType TEXT,
            Category TEXT,
            ProfileGUID TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        networkList.ExecuteNonQuery();

        using var installedPrograms = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS installed_programs_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            DisplayName TEXT,
            DisplayVersion TEXT,
            Publisher TEXT,
            InstallDate TEXT,
            InstallLocation TEXT,
            InstallSource TEXT,
            UninstallString TEXT,
            EstimatedSizeKB INTEGER,
            HelpLink TEXT,
            URLInfoAbout TEXT,
            SystemComponent INTEGER,
            Source TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        installedPrograms.ExecuteNonQuery();

        using var autorun = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS autorun_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            Name TEXT,
            Command TEXT,
            RegistryLocation TEXT,
            RunType TEXT,
            HiveSource TEXT,
            UserProfile TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        autorun.ExecuteNonQuery();

        using var userProfiles = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS user_profiles_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            SID TEXT,
            Username TEXT,
            ProfilePath TEXT,
            ProfileLoadTime TEXT,
            ProfileUnloadTime TEXT,
            DomainProfileLoadTime TEXT,
            State INTEGER,
            IsLoaded INTEGER,
            AccountCategory TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        userProfiles.ExecuteNonQuery();

        using var windowsUpdates = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS windows_updates_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            PackageName TEXT,
            KBNumber TEXT,
            Architecture TEXT,
            Version TEXT,
            CurrentState INTEGER,
            StateDescription TEXT,
            InstallTime TEXT,
            LastUpdateTime TEXT,
            InstallClient TEXT,
            InstallUser TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        windowsUpdates.ExecuteNonQuery();

        using var defender = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS defender_exclusions_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            ExclusionType TEXT,
            ExclusionValue TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        defender.ExecuteNonQuery();

        using var systemInfo = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS system_info_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            PropertyKey TEXT,
            PropertyValue TEXT,
            Category TEXT,
            HivePath TEXT,
            RegistryKey TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        systemInfo.ExecuteNonQuery();
    }

    public static NetworkListParseResult ParseNetworkList(
        string softwareHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(softwareHivePath) ||
            !File.Exists(softwareHivePath))
        {
            return new NetworkListParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(softwareHivePath);
            const string profilesPath = @"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles";
            var profilesKey = hive.GetKey(profilesPath);
            if (profilesKey?.SubKeys == null)
                return new NetworkListParseResult(0);

            var signatures = BuildSignatureLookup(hive);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var profileStub in profilesKey.SubKeys)
            {
                string profileGuid = profileStub.KeyName ?? "";
                var profileKey = hive.GetKey($@"{profilesPath}\{profileGuid}");
                if (profileKey?.Values == null || profileKey.Values.Count == 0)
                    continue;

                string profileName = Value(profileKey, "ProfileName");
                string description = Value(profileKey, "Description");
                string dnsSuffix = Value(profileKey, "DnsSuffix");
                string networkType = DecodeNetworkType(Value(profileKey, "NameType"));
                string category = DecodeCategory(Value(profileKey, "Category"));
                string firstConnect = ParseSystemTime(RawValue(profileKey, "DateCreated"));
                string lastConnect = ParseSystemTime(RawValue(profileKey, "DateLastConnected"));

                string gatewayMac = "";
                string ssid = "";
                if (signatures.TryGetValue(profileGuid, out var signature))
                {
                    gatewayMac = signature.GatewayMac;
                    ssid = signature.Ssid;
                    if (string.IsNullOrWhiteSpace(dnsSuffix))
                        dnsSuffix = signature.DnsSuffix;
                }

                string potentialActivity = networkType == "Wireless"
                    ? "Wireless Network Connection"
                    : "Network Connection";

                using var command = new SQLiteCommand(@"INSERT INTO networklist_results
                    (ArtifactType, ProfileName, Description, SSID, DnsSuffix, DefaultGatewayMac,
                     FirstConnect, LastConnect, NetworkType, Category, ProfileGUID, HivePath,
                     Potential_Activity, File, Label, Comment)
                    VALUES ('NetworkList', @ProfileName, @Description, @SSID, @DnsSuffix,
                     @DefaultGatewayMac, @FirstConnect, @LastConnect, @NetworkType, @Category,
                     @ProfileGUID, @HivePath, @PotentialActivity, @File, '', '')",
                    connection,
                    transaction);
                command.Parameters.AddWithValue("@ProfileName", profileName);
                command.Parameters.AddWithValue("@Description", description);
                command.Parameters.AddWithValue("@SSID", ssid);
                command.Parameters.AddWithValue("@DnsSuffix", dnsSuffix);
                command.Parameters.AddWithValue("@DefaultGatewayMac", gatewayMac);
                command.Parameters.AddWithValue("@FirstConnect", firstConnect);
                command.Parameters.AddWithValue("@LastConnect", lastConnect);
                command.Parameters.AddWithValue("@NetworkType", networkType);
                command.Parameters.AddWithValue("@Category", category);
                command.Parameters.AddWithValue("@ProfileGUID", profileGuid);
                command.Parameters.AddWithValue("@HivePath", softwareHivePath);
                command.Parameters.AddWithValue("@PotentialActivity", potentialActivity);
                command.Parameters.AddWithValue("@File", Path.GetFileName(softwareHivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "networklist_results", softwareHivePath, $@"{profilesPath}\{profileGuid}", profileKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"NetworkList: {inserted:N0} entries");

            return new NetworkListParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"NetworkList parse error from {softwareHivePath}: {ex}");
            return new NetworkListParseResult(0);
        }
    }

    public static InstalledProgramsParseResult ParseInstalledProgramsHklm(
        string softwareHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(softwareHivePath) ||
            !File.Exists(softwareHivePath))
        {
            return new InstalledProgramsParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(softwareHivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = 0;
            inserted += ProcessUninstallKey(hive, @"Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM\SOFTWARE", softwareHivePath, connection, transaction);
            inserted += ProcessUninstallKey(hive, @"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM\SOFTWARE\Wow6432Node (32-bit)", softwareHivePath, connection, transaction);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Installed Programs HKLM: {inserted:N0} entries");

            return new InstalledProgramsParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Installed Programs HKLM parse error from {softwareHivePath}: {ex}");
            return new InstalledProgramsParseResult(0);
        }
    }

    public static InstalledProgramsParseResult ParseInstalledProgramsHkcu(
        string ntuserHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(ntuserHivePath) ||
            !File.Exists(ntuserHivePath))
        {
            return new InstalledProgramsParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(ntuserHivePath);
            string username = InferUserProfileFromHivePath(ntuserHivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = ProcessUninstallKey(
                hive,
                @"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                $"HKCU {username}",
                ntuserHivePath,
                connection,
                transaction);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Installed Programs HKCU ({username}): {inserted:N0} entries");

            return new InstalledProgramsParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Installed Programs HKCU parse error from {ntuserHivePath}: {ex}");
            return new InstalledProgramsParseResult(0);
        }
    }

    public static AutorunParseResult ParseAutorunHklm(
        string softwareHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(softwareHivePath) ||
            !File.Exists(softwareHivePath))
        {
            return new AutorunParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(softwareHivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = 0;
            const string hklm = @"HKLM\SOFTWARE";
            inserted += ProcessRunKey(hive, @"Microsoft\Windows\CurrentVersion\Run", "Run", hklm, "", softwareHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", hklm, "", softwareHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Microsoft\Windows\CurrentVersion\RunOnceEx", "RunOnceEx", hklm, "", softwareHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Microsoft\Windows\CurrentVersion\RunServices", "RunServices", hklm, "", softwareHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Microsoft\Windows\CurrentVersion\RunServicesOnce", "RunServicesOnce", hklm, "", softwareHivePath, connection, transaction);

            const string hklm32 = @"HKLM\SOFTWARE\Wow6432Node";
            inserted += ProcessRunKey(hive, @"Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "Run", hklm32, "", softwareHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", hklm32, "", softwareHivePath, connection, transaction);
            inserted += ProcessWinlogonAutoruns(hive, softwareHivePath, hklm, connection, transaction);
            inserted += ProcessActiveSetup(hive, softwareHivePath, hklm, connection, transaction);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Autorun HKLM: {inserted:N0} entries");

            return new AutorunParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Autorun HKLM parse error from {softwareHivePath}: {ex}");
            return new AutorunParseResult(0);
        }
    }

    public static AutorunParseResult ParseAutorunHkcu(
        string ntuserHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(ntuserHivePath) ||
            !File.Exists(ntuserHivePath))
        {
            return new AutorunParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(ntuserHivePath);
            string username = InferUserProfileFromHivePath(ntuserHivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = 0;
            inserted += ProcessRunKey(hive, @"Software\Microsoft\Windows\CurrentVersion\Run", "Run", "HKCU", username, ntuserHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", "HKCU", username, ntuserHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Software\Microsoft\Windows\CurrentVersion\RunOnceEx", "RunOnceEx", "HKCU", username, ntuserHivePath, connection, transaction);
            inserted += ProcessRunKey(hive, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"Policies\Explorer\Run", "HKCU", username, ntuserHivePath, connection, transaction);
            inserted += ProcessWindowsNtAutoruns(hive, ntuserHivePath, username, connection, transaction);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Autorun HKCU ({username}): {inserted:N0} entries");

            return new AutorunParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Autorun HKCU parse error from {ntuserHivePath}: {ex}");
            return new AutorunParseResult(0);
        }
    }

    public static UserProfilesParseResult ParseUserProfiles(
        string softwareHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(softwareHivePath) ||
            !File.Exists(softwareHivePath))
        {
            return new UserProfilesParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(softwareHivePath);
            const string profileListPath = @"Microsoft\Windows NT\CurrentVersion\ProfileList";
            var root = hive.GetKey(profileListPath);
            if (root?.SubKeys == null)
                return new UserProfilesParseResult(0);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var sidStub in root.SubKeys)
            {
                string sid = sidStub.KeyName ?? "";
                var profileKey = hive.GetKey($@"{profileListPath}\{sid}");
                if (profileKey?.Values == null)
                    continue;

                string profilePath = Value(profileKey, "ProfileImagePath");
                string username = string.IsNullOrWhiteSpace(profilePath)
                    ? ""
                    : Path.GetFileName(profilePath.TrimEnd('\\'));
                int state = IntValue(profileKey, "State", 0);
                int isLoaded = (state & 0x100) != 0 ? 1 : 0;

                using var command = new SQLiteCommand(@"INSERT INTO user_profiles_results
                    (ArtifactType, SID, Username, ProfilePath, ProfileLoadTime, ProfileUnloadTime,
                     DomainProfileLoadTime, State, IsLoaded, AccountCategory, Potential_Activity,
                     File, Label, Comment)
                    VALUES ('User Profile', @SID, @Username, @ProfilePath, @ProfileLoadTime,
                     @ProfileUnloadTime, @DomainProfileLoadTime, @State, @IsLoaded, @AccountCategory,
                     'User Profile', @File, '', '')", connection, transaction);
                command.Parameters.AddWithValue("@SID", sid);
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@ProfilePath", profilePath);
                command.Parameters.AddWithValue("@ProfileLoadTime", FileTimeFromLowHigh(profileKey, "LocalProfileLoadTimeLow", "LocalProfileLoadTimeHigh"));
                command.Parameters.AddWithValue("@ProfileUnloadTime", FileTimeFromLowHigh(profileKey, "LocalProfileUnloadTimeLow", "LocalProfileUnloadTimeHigh"));
                command.Parameters.AddWithValue("@DomainProfileLoadTime", FileTimeFromLowHigh(profileKey, "ProfileLoadTimeLow", "ProfileLoadTimeHigh"));
                command.Parameters.AddWithValue("@State", state);
                command.Parameters.AddWithValue("@IsLoaded", isLoaded);
                command.Parameters.AddWithValue("@AccountCategory", ClassifySid(sid));
                command.Parameters.AddWithValue("@File", Path.GetFileName(softwareHivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "user_profiles_results", softwareHivePath, $@"{profileListPath}\{sid}", profileKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"User Profiles: {inserted:N0} entries");

            return new UserProfilesParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"User Profiles parse error from {softwareHivePath}: {ex}");
            return new UserProfilesParseResult(0);
        }
    }

    public static WindowsUpdatesParseResult ParseWindowsUpdates(
        string softwareHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(softwareHivePath) ||
            !File.Exists(softwareHivePath))
        {
            return new WindowsUpdatesParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(softwareHivePath);
            const string packagesPath = @"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages";
            var packagesKey = hive.GetKey(packagesPath);
            if (packagesKey?.SubKeys == null)
                return new WindowsUpdatesParseResult(0);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;
            int installed = 0;
            var kbRegex = new Regex(@"KB\d{6,7}", RegexOptions.IgnoreCase);

            foreach (var packageStub in packagesKey.SubKeys)
            {
                string packageName = packageStub.KeyName ?? "";
                if (string.IsNullOrWhiteSpace(packageName))
                    continue;

                string packageKeyPath = $@"{packagesPath}\{packageName}";
                var packageKey = hive.GetKey(packageKeyPath);
                if (packageKey?.Values == null)
                    continue;

                string kb = "";
                Match match = kbRegex.Match(packageName);
                if (match.Success)
                    kb = match.Value.ToUpperInvariant();

                string architecture = "";
                string version = "";
                int versionMarker = packageName.IndexOf("~~", StringComparison.Ordinal);
                if (versionMarker >= 0)
                    version = packageName[(versionMarker + 2)..];
                string[] parts = packageName.Split('~');
                if (parts.Length >= 3 &&
                    parts[2] is "amd64" or "x86" or "arm64" or "wow64" or "msil")
                {
                    architecture = parts[2];
                }

                int currentState = IntValue(packageKey, "CurrentState", -1);
                string installTime = FileTimeFromHighLow(packageKey, "InstallTimeHigh", "InstallTimeLow");
                string lastUpdate = FileTimeFromHighLow(packageKey, "LastUpdateTimeHigh", "LastUpdateTimeLow");
                bool keep = !string.IsNullOrWhiteSpace(kb) || currentState == 112 || !string.IsNullOrWhiteSpace(installTime);
                if (!keep)
                    continue;

                string activity = currentState == 112 ? "Windows Update (Installed)" : "Windows Update";
                if (currentState == 112)
                    installed++;

                using var command = new SQLiteCommand(@"INSERT INTO windows_updates_results
                    (ArtifactType, PackageName, KBNumber, Architecture, Version, CurrentState,
                     StateDescription, InstallTime, LastUpdateTime, InstallClient, InstallUser,
                     RegistryKey, HivePath, Potential_Activity, File, Label, Comment)
                    VALUES ('Windows Update', @PackageName, @KBNumber, @Architecture, @Version,
                     @CurrentState, @StateDescription, @InstallTime, @LastUpdateTime, @InstallClient,
                     @InstallUser, @RegistryKey, @HivePath, @PotentialActivity, @File, '', '')",
                    connection,
                    transaction);
                command.Parameters.AddWithValue("@PackageName", packageName);
                command.Parameters.AddWithValue("@KBNumber", kb);
                command.Parameters.AddWithValue("@Architecture", architecture);
                command.Parameters.AddWithValue("@Version", version);
                command.Parameters.AddWithValue("@CurrentState", currentState);
                command.Parameters.AddWithValue("@StateDescription", WindowsUpdateState(currentState));
                command.Parameters.AddWithValue("@InstallTime", installTime);
                command.Parameters.AddWithValue("@LastUpdateTime", lastUpdate);
                command.Parameters.AddWithValue("@InstallClient", Value(packageKey, "InstallClient"));
                command.Parameters.AddWithValue("@InstallUser", Value(packageKey, "InstallUser"));
                command.Parameters.AddWithValue("@RegistryKey", packageKeyPath);
                command.Parameters.AddWithValue("@HivePath", softwareHivePath);
                command.Parameters.AddWithValue("@PotentialActivity", activity);
                command.Parameters.AddWithValue("@File", Path.GetFileName(softwareHivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "windows_updates_results", softwareHivePath, packageKeyPath, packageKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Windows Updates: {inserted:N0} entries ({installed:N0} installed)");

            return new WindowsUpdatesParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Windows Updates parse error from {softwareHivePath}: {ex}");
            return new WindowsUpdatesParseResult(0);
        }
    }

    public static DefenderExclusionsParseResult ParseDefenderExclusions(
        string softwareHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(softwareHivePath) ||
            !File.Exists(softwareHivePath))
        {
            return new DefenderExclusionsParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(softwareHivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            const string baseKey = @"Microsoft\Windows Defender\Exclusions";
            foreach (var (subKey, typeLabel) in new[]
            {
                ("Paths", "Path"),
                ("Extensions", "Extension"),
                ("Processes", "Process"),
                ("IpAddresses", "IpAddress"),
                ("TemporaryPaths", "TemporaryPath")
            })
            {
                string fullKeyPath = $@"{baseKey}\{subKey}";
                var key = hive.GetKey(fullKeyPath);
                if (key?.Values == null)
                    continue;

                foreach (var value in key.Values)
                {
                    string exclusionValue = value.ValueName ?? "";
                    if (string.IsNullOrWhiteSpace(exclusionValue) ||
                        exclusionValue.Equals("(default)", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    using var command = new SQLiteCommand(@"INSERT INTO defender_exclusions_results
                        (ArtifactType, ExclusionType, ExclusionValue, RegistryKey, HivePath,
                         Potential_Activity, File, Label, Comment)
                        VALUES ('Defender Exclusion', @ExclusionType, @ExclusionValue, @RegistryKey,
                         @HivePath, 'Defender Exclusion', @File, '', '')", connection, transaction);
                    command.Parameters.AddWithValue("@ExclusionType", typeLabel);
                    command.Parameters.AddWithValue("@ExclusionValue", exclusionValue);
                    command.Parameters.AddWithValue("@RegistryKey", fullKeyPath);
                    command.Parameters.AddWithValue("@HivePath", softwareHivePath);
                    command.Parameters.AddWithValue("@File", Path.GetFileName(softwareHivePath));
                    command.ExecuteNonQuery();
                    ArtifactProvenance.RecordKey(connection, transaction, "defender_exclusions_results", softwareHivePath, fullKeyPath, key.LastWriteTime);
                    inserted++;
                }
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Defender Exclusions: {inserted:N0} entries");

            return new DefenderExclusionsParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Defender Exclusions parse error from {softwareHivePath}: {ex}");
            return new DefenderExclusionsParseResult(0);
        }
    }

    public static SoftwareSystemInfoParseResult ParseSystemInfoFromSoftware(
        string softwareHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(softwareHivePath) ||
            !File.Exists(softwareHivePath))
        {
            return new SoftwareSystemInfoParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(softwareHivePath);
            const string currentVersionPath = @"Microsoft\Windows NT\CurrentVersion";
            var currentVersion = hive.GetKey(currentVersionPath);
            if (currentVersion?.Values == null)
                return new SoftwareSystemInfoParseResult(0);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (string valueName in new[]
            {
                "ProductName",
                "CurrentBuild",
                "CurrentBuildNumber",
                "UBR",
                "EditionID",
                "InstallationType",
                "SystemRoot",
                "PathName"
            })
            {
                inserted += InsertSystemInfo(connection, transaction, softwareHivePath, currentVersionPath, "OS", valueName, Value(currentVersion, valueName), currentVersion?.LastWriteTime);
            }

            string displayVersion = Value(currentVersion, "DisplayVersion");
            if (string.IsNullOrWhiteSpace(displayVersion))
                displayVersion = Value(currentVersion, "ReleaseId");
            inserted += InsertSystemInfo(connection, transaction, softwareHivePath, currentVersionPath, "OS", "DisplayVersion", displayVersion, currentVersion?.LastWriteTime);

            foreach (string valueName in new[] { "RegisteredOwner", "RegisteredOrganization", "ProductId" })
                inserted += InsertSystemInfo(connection, transaction, softwareHivePath, currentVersionPath, "Licensing", valueName, Value(currentVersion, valueName), currentVersion?.LastWriteTime);

            inserted += InsertSystemInfo(connection, transaction, softwareHivePath, currentVersionPath, "Install", "InstallDate", SystemInfoUnixTimeToString(Value(currentVersion, "InstallDate")), currentVersion?.LastWriteTime);
            inserted += InsertSystemInfo(connection, transaction, softwareHivePath, currentVersionPath, "Install", "InstallTime", SystemInfoFileTimeToString(RawValue(currentVersion, "InstallTime")), currentVersion?.LastWriteTime);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"System Information (SOFTWARE): {inserted:N0} properties");

            return new SoftwareSystemInfoParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"System Information SOFTWARE parse error from {softwareHivePath}: {ex}");
            return new SoftwareSystemInfoParseResult(0);
        }
    }

    private static int InsertSystemInfo(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string hivePath,
        string registryKey,
        string category,
        string propertyKey,
        string propertyValue,
        DateTimeOffset? keyLastWrite)
    {
        if (string.IsNullOrWhiteSpace(propertyValue))
            return 0;

        using var command = new SQLiteCommand(@"INSERT INTO system_info_results
            (ArtifactType, PropertyKey, PropertyValue, Category, HivePath, RegistryKey,
             Potential_Activity, File, Label, Comment)
            VALUES ('System Info', @PropertyKey, @PropertyValue, @Category, @HivePath,
             @RegistryKey, 'System Configuration', @File, '', '')",
            connection,
            transaction);
        command.Parameters.AddWithValue("@PropertyKey", propertyKey);
        command.Parameters.AddWithValue("@PropertyValue", propertyValue);
        command.Parameters.AddWithValue("@Category", category);
        command.Parameters.AddWithValue("@HivePath", hivePath);
        command.Parameters.AddWithValue("@RegistryKey", registryKey);
        command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
        command.ExecuteNonQuery();
        ArtifactProvenance.RecordKey(connection, transaction, "system_info_results", hivePath, registryKey, keyLastWrite);
        return 1;
    }

    private static string SystemInfoUnixTimeToString(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || !long.TryParse(raw, out long timestamp) || timestamp <= 0)
            return "";

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        }
        catch
        {
            return "";
        }
    }

    private static string SystemInfoFileTimeToString(byte[]? raw)
    {
        if (raw == null || raw.Length < 8)
            return "";

        try
        {
            long fileTime = BitConverter.ToInt64(raw, 0);
            return fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime).ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
        }
        catch
        {
            return "";
        }
    }

    private sealed record NetworkSignature(string GatewayMac, string Ssid, string DnsSuffix);

    private static int ProcessUninstallKey(
        RegistryHiveOnDemand hive,
        string basePath,
        string source,
        string hivePath,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var root = hive.GetKey(basePath);
        if (root?.SubKeys == null)
            return 0;

        int count = 0;
        foreach (var subKey in root.SubKeys)
        {
            string appKeyPath = $@"{basePath}\{subKey.KeyName}";
            var appKey = hive.GetKey(appKeyPath);
            if (appKey?.Values == null)
                continue;

            string displayName = Value(appKey, "DisplayName");
            if (string.IsNullOrWhiteSpace(displayName))
                continue;

            using var command = new SQLiteCommand(@"INSERT INTO installed_programs_results
                (ArtifactType, DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation,
                 InstallSource, UninstallString, EstimatedSizeKB, HelpLink, URLInfoAbout, SystemComponent,
                 Source, RegistryKey, HivePath, Potential_Activity, File, Label, Comment)
                VALUES ('Installed Program', @DisplayName, @DisplayVersion, @Publisher, @InstallDate,
                 @InstallLocation, @InstallSource, @UninstallString, @EstimatedSizeKB, @HelpLink,
                 @URLInfoAbout, @SystemComponent, @Source, @RegistryKey, @HivePath,
                 'Installed Program', @File, '', '')", connection, transaction);
            command.Parameters.AddWithValue("@DisplayName", displayName);
            command.Parameters.AddWithValue("@DisplayVersion", Value(appKey, "DisplayVersion"));
            command.Parameters.AddWithValue("@Publisher", Value(appKey, "Publisher"));
            command.Parameters.AddWithValue("@InstallDate", ParseInstallDate(Value(appKey, "InstallDate")));
            command.Parameters.AddWithValue("@InstallLocation", Value(appKey, "InstallLocation"));
            command.Parameters.AddWithValue("@InstallSource", Value(appKey, "InstallSource"));
            command.Parameters.AddWithValue("@UninstallString", Value(appKey, "UninstallString"));
            command.Parameters.AddWithValue("@EstimatedSizeKB", LongValue(appKey, "EstimatedSize", 0));
            command.Parameters.AddWithValue("@HelpLink", Value(appKey, "HelpLink"));
            command.Parameters.AddWithValue("@URLInfoAbout", Value(appKey, "URLInfoAbout"));
            command.Parameters.AddWithValue("@SystemComponent", IntValue(appKey, "SystemComponent", 0));
            command.Parameters.AddWithValue("@Source", source);
            command.Parameters.AddWithValue("@RegistryKey", appKeyPath);
            command.Parameters.AddWithValue("@HivePath", hivePath);
            command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
            command.ExecuteNonQuery();
            ArtifactProvenance.RecordKey(connection, transaction, "installed_programs_results", hivePath, appKeyPath, appKey.LastWriteTime);
            count++;
        }

        return count;
    }

    private static int ProcessRunKey(
        RegistryHiveOnDemand hive,
        string keyPath,
        string runType,
        string hiveSource,
        string userProfile,
        string hivePath,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var key = hive.GetKey(keyPath);
        if (key?.Values == null)
            return 0;

        int count = 0;
        foreach (var value in key.Values)
        {
            string valueName = value.ValueName ?? "";
            if (string.IsNullOrWhiteSpace(valueName) ||
                valueName.Equals("(default)", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            InsertAutorun(connection, transaction, hivePath, keyPath, runType, hiveSource, userProfile, valueName, value.ValueData ?? "", key.LastWriteTime);
            count++;
        }

        return count;
    }

    private static int ProcessWinlogonAutoruns(
        RegistryHiveOnDemand hive,
        string hivePath,
        string hiveSource,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        const string keyPath = @"Microsoft\Windows NT\CurrentVersion\Winlogon";
        var key = hive.GetKey(keyPath);
        if (key?.Values == null)
            return 0;

        int count = 0;
        foreach (string name in new[] { "Shell", "Userinit", "Taskman" })
        {
            string command = Value(key, name);
            if (string.IsNullOrWhiteSpace(command))
                continue;

            InsertAutorun(connection, transaction, hivePath, keyPath, $"Winlogon {name}", hiveSource, "", name, command, key.LastWriteTime);
            count++;
        }

        return count;
    }

    private static int ProcessActiveSetup(
        RegistryHiveOnDemand hive,
        string hivePath,
        string hiveSource,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        const string basePath = @"Microsoft\Active Setup\Installed Components";
        var key = hive.GetKey(basePath);
        if (key?.SubKeys == null)
            return 0;

        int count = 0;
        foreach (var componentStub in key.SubKeys)
        {
            string componentPath = $@"{basePath}\{componentStub.KeyName}";
            var componentKey = hive.GetKey(componentPath);
            if (componentKey?.Values == null)
                continue;

            string stubPath = Value(componentKey, "StubPath");
            if (string.IsNullOrWhiteSpace(stubPath))
                continue;

            string name = Value(componentKey, "(default)");
            if (string.IsNullOrWhiteSpace(name))
                name = componentStub.KeyName ?? "";
            InsertAutorun(connection, transaction, hivePath, componentPath, "Active Setup StubPath", hiveSource, "", name, stubPath, componentKey.LastWriteTime);
            count++;
        }

        return count;
    }

    private static int ProcessWindowsNtAutoruns(
        RegistryHiveOnDemand hive,
        string hivePath,
        string username,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        const string keyPath = @"Software\Microsoft\Windows NT\CurrentVersion\Windows";
        var key = hive.GetKey(keyPath);
        if (key?.Values == null)
            return 0;

        int count = 0;
        foreach (var (valueName, runType) in new[] { ("Load", "Windows Load"), ("Run", "Windows Run") })
        {
            string command = Value(key, valueName);
            if (string.IsNullOrWhiteSpace(command))
                continue;

            InsertAutorun(connection, transaction, hivePath, keyPath, runType, "HKCU", username, valueName, command, key.LastWriteTime);
            count++;
        }

        return count;
    }

    private static void InsertAutorun(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string hivePath,
        string registryLocation,
        string runType,
        string hiveSource,
        string userProfile,
        string name,
        string commandText,
        DateTimeOffset? keyLastWrite)
    {
        using var command = new SQLiteCommand(@"INSERT INTO autorun_results
            (ArtifactType, Name, Command, RegistryLocation, RunType, HiveSource, UserProfile,
             HivePath, Potential_Activity, File, Label, Comment)
            VALUES ('Autorun', @Name, @Command, @RegistryLocation, @RunType, @HiveSource,
             @UserProfile, @HivePath, 'Persistence Mechanism', @File, '', '')",
            connection,
            transaction);
        command.Parameters.AddWithValue("@Name", name ?? "");
        command.Parameters.AddWithValue("@Command", commandText ?? "");
        command.Parameters.AddWithValue("@RegistryLocation", registryLocation ?? "");
        command.Parameters.AddWithValue("@RunType", runType ?? "");
        command.Parameters.AddWithValue("@HiveSource", hiveSource ?? "");
        command.Parameters.AddWithValue("@UserProfile", userProfile ?? "");
        command.Parameters.AddWithValue("@HivePath", hivePath ?? "");
        command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath ?? ""));
        command.ExecuteNonQuery();
        ArtifactProvenance.RecordKey(connection, transaction, "autorun_results", hivePath ?? "", registryLocation ?? "", keyLastWrite);
    }

    private static Dictionary<string, NetworkSignature> BuildSignatureLookup(RegistryHiveOnDemand hive)
    {
        var result = new Dictionary<string, NetworkSignature>(StringComparer.OrdinalIgnoreCase);
        foreach (string basePath in new[]
        {
            @"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed",
            @"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
        })
        {
            var parent = hive.GetKey(basePath);
            if (parent?.SubKeys == null)
                continue;

            foreach (var stub in parent.SubKeys)
            {
                var key = hive.GetKey($@"{basePath}\{stub.KeyName}");
                if (key?.Values == null)
                    continue;

                string guid = Value(key, "ProfileGuid");
                if (string.IsNullOrWhiteSpace(guid) || result.ContainsKey(guid))
                    continue;

                byte[] macRaw = RawValue(key, "DefaultGatewayMac") ?? Array.Empty<byte>();
                string mac = macRaw.Length >= 6 ? BitConverter.ToString(macRaw, 0, 6).Replace("-", ":") : "";
                result[guid] = new NetworkSignature(mac, Value(key, "FirstNetwork"), Value(key, "DnsSuffix"));
            }
        }

        return result;
    }

    private static string DecodeNetworkType(string raw)
    {
        return int.TryParse(raw, out int value)
            ? value switch { 6 => "Wired", 23 => "Broadband", 71 => "Wireless", _ => $"Type {value}" }
            : "Unknown";
    }

    private static string DecodeCategory(string raw)
    {
        return int.TryParse(raw, out int value)
            ? value switch { 0 => "Public", 1 => "Private", 2 => "Domain", _ => $"Cat {value}" }
            : "Public";
    }

    private static string ParseInstallDate(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "";

        raw = raw.Trim();
        return raw.Length == 8 &&
               raw.All(char.IsDigit) &&
               DateTime.TryParseExact(raw, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out DateTime date)
            ? date.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)
            : raw;
    }

    private static string FileTimeFromLowHigh(dynamic key, string lowName, string highName)
    {
        uint low = UIntValue(key, lowName, 0);
        uint high = UIntValue(key, highName, 0);
        return FileTimeToString(high, low, "yyyy-MM-ddTHH:mm:ss.fffZ");
    }

    private static string FileTimeFromHighLow(dynamic key, string highName, string lowName)
    {
        uint high = UIntValue(key, highName, 0);
        uint low = UIntValue(key, lowName, 0);
        return FileTimeToString(high, low, "yyyy-MM-dd HH:mm:ss");
    }

    private static string FileTimeToString(uint high, uint low, string format)
    {
        if (high == 0 && low == 0)
            return "";

        try
        {
            long fileTime = ((long)high << 32) | low;
            return fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime).ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
        }
        catch
        {
            return "";
        }
    }

    private static string ClassifySid(string sid)
    {
        if (string.IsNullOrWhiteSpace(sid)) return "Other";
        if (sid == "S-1-5-18") return "LocalSystem";
        if (sid == "S-1-5-19") return "LocalService";
        if (sid == "S-1-5-20") return "NetworkService";
        if (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
        {
            int lastDash = sid.LastIndexOf('-');
            if (lastDash > 0 && int.TryParse(sid[(lastDash + 1)..], out int rid))
            {
                return rid switch
                {
                    500 => "Administrator",
                    501 => "Guest",
                    503 => "DefaultAccount",
                    504 => "WDAGUtilityAccount",
                    _ => rid >= 1000 ? "Local User" : "Other"
                };
            }

            return "Local User";
        }

        return "Other";
    }

    private static string WindowsUpdateState(int state)
    {
        return state switch
        {
            112 => "Installed",
            80 => "Absent",
            64 => "Staged",
            48 => "Superseded",
            32 => "Partially Installed",
            16 => "Resolved",
            _ => $"Unknown ({state})"
        };
    }

    private static string ParseSystemTime(byte[]? raw)
    {
        if (raw == null || raw.Length < 16)
            return string.Empty;

        try
        {
            int year = BitConverter.ToUInt16(raw, 0);
            int month = BitConverter.ToUInt16(raw, 2);
            int day = BitConverter.ToUInt16(raw, 6);
            int hour = BitConverter.ToUInt16(raw, 8);
            int minute = BitConverter.ToUInt16(raw, 10);
            int second = BitConverter.ToUInt16(raw, 12);
            int millisecond = BitConverter.ToUInt16(raw, 14);
            return year is >= 1601 and <= 2100 && month is >= 1 and <= 12 && day is >= 1 and <= 31
                ? new DateTime(year, month, day, hour, minute, second, millisecond).ToString("yyyy-MM-dd HH:mm:ss.fff", System.Globalization.CultureInfo.InvariantCulture)
                : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string Value(dynamic? key, string valueName)
    {
        if (key?.Values == null) return "";
        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, valueName, StringComparison.OrdinalIgnoreCase))
            {
                string text = value.ValueData ?? "";
                int terminator = text.IndexOf('\0');
                return terminator < 0 ? text : text[..terminator];
            }
        }

        return "";
    }

    private static int IntValue(dynamic key, string valueName, int defaultValue)
    {
        return int.TryParse(Value(key, valueName), out int value) ? value : defaultValue;
    }

    private static uint UIntValue(dynamic key, string valueName, uint defaultValue)
    {
        return uint.TryParse(Value(key, valueName), out uint value) ? value : defaultValue;
    }

    private static long LongValue(dynamic key, string valueName, long defaultValue)
    {
        return long.TryParse(Value(key, valueName), out long value) ? value : defaultValue;
    }

    private static string InferUserProfileFromHivePath(string hivePath)
    {
        string normalized = hivePath.Replace('/', '\\');
        string marker = "\\Users\\";
            int index = normalized.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index >= 0)
        {
            int start = index + marker.Length;
            int end = normalized.IndexOf('\\', start);
            if (end > start)
                return normalized[start..end];
        }

        return Path.GetFileName(Path.GetDirectoryName(hivePath)) ?? "";
    }

    private static byte[]? RawValue(dynamic? key, string valueName)
    {
        if (key?.Values == null) return null;
        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, valueName, StringComparison.OrdinalIgnoreCase))
                return value.ValueDataRaw;
        }

        return null;
    }
}
