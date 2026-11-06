using Registry;
using System.Data.SQLite;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record BamDamParseResult(int Inserted);

public sealed record ServicesParseResult(int Inserted);

public sealed record NetworkInterfacesParseResult(int Inserted);

public sealed record SystemInfoParseResult(int Inserted);

public sealed record FirewallRulesParseResult(int Inserted);

public sealed record ShimCacheParseResult(int Inserted);

public static class SystemRegistryParsers
{
    private static readonly string[] BamDamKeyPaths =
    {
        @"ControlSet001\Services\bam\State\UserSettings",
        @"ControlSet001\Services\bam\UserSettings",
        @"ControlSet001\Services\dam\State\UserSettings"
    };

    public static void CreateTables(SQLiteConnection connection)
    {
        using var bam = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS bam_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            ExecutableName TEXT,
            ExecutablePath TEXT,
            LastRunTime TEXT,
            UserSID TEXT,
            UserProfile TEXT,
            SourceType TEXT,
            Potential_Activity TEXT,
            SourceHive TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        bam.ExecuteNonQuery();

        using var services = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS services_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            Name TEXT,
            DisplayName TEXT,
            Description TEXT,
            ImagePath TEXT,
            ServiceDll TEXT,
            StartType TEXT,
            StartValue INTEGER,
            ServiceType TEXT,
            TypeValue INTEGER,
            ObjectName TEXT,
            ErrorControl INTEGER,
            Group_ TEXT,
            DependsOn TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        services.ExecuteNonQuery();

        using var networkInterfaces = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS network_interfaces_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            InterfaceGuid TEXT,
            InterfaceDescription TEXT,
            EnableDHCP INTEGER,
            ConnectionType TEXT,
            IPAddress TEXT,
            SubnetMask TEXT,
            DefaultGateway TEXT,
            DhcpIPAddress TEXT,
            DhcpSubnetMask TEXT,
            DhcpDefaultGateway TEXT,
            NameServer TEXT,
            DhcpNameServer TEXT,
            Domain TEXT,
            DhcpDomain TEXT,
            DhcpServer TEXT,
            LeaseObtainedTime TEXT,
            LeaseTerminatesTime TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        networkInterfaces.ExecuteNonQuery();

        using var systemInfo = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS system_info_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            PropertyKey TEXT,
            PropertyValue TEXT,
            RawPropertyValue TEXT,
            Category TEXT,
            HivePath TEXT,
            RegistryKey TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        systemInfo.ExecuteNonQuery();
        bool hasRawProperty;
        using (var schema = new SQLiteCommand("PRAGMA table_info(system_info_results)", connection))
        using (var columns = schema.ExecuteReader())
        {
            hasRawProperty = false;
            while (columns.Read()) hasRawProperty |= columns.GetString(1) == "RawPropertyValue";
        }
        if (!hasRawProperty) new SQLiteCommand("ALTER TABLE system_info_results ADD COLUMN RawPropertyValue TEXT", connection).ExecuteNonQuery();

        using var firewallRules = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS firewall_rules_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            RuleId TEXT,
            RuleName TEXT,
            Description TEXT,
            Action TEXT,
            Active TEXT,
            Direction TEXT,
            Protocol TEXT,
            LocalPort TEXT,
            RemotePort TEXT,
            ApplicationPath TEXT,
            ServiceName TEXT,
            LocalAddress TEXT,
            RemoteAddress TEXT,
            Profile TEXT,
            SchemaVersion TEXT,
            RawRule TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        firewallRules.ExecuteNonQuery();

        using var shimCache = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS shimcache_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            Path TEXT,
            LastModified DATETIME,
            Executed TEXT,
            FileSize INTEGER,
            SequenceNumber INTEGER,
            ControlSet TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        shimCache.ExecuteNonQuery();
    }

    public static BamDamParseResult ParseBamDam(
        string systemHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(systemHivePath) ||
            !File.Exists(systemHivePath))
        {
            return new BamDamParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (string keyPath in BamDamKeyPaths)
            {
                var parentKey = hive.GetKey(keyPath);
                if (parentKey?.SubKeys == null)
                    continue;

                string sourceType = keyPath.Contains(@"\dam\", StringComparison.OrdinalIgnoreCase) ? "DAM" : "BAM";
                foreach (var sidStub in parentKey.SubKeys)
                {
                    string sid = sidStub.KeyName ?? "";
                    var sidKey = hive.GetKey($@"{keyPath}\{sid}");
                    if (sidKey?.Values == null)
                        continue;

                    foreach (var value in sidKey.Values)
                    {
                        string valueName = value.ValueName ?? "";
                        if (valueName.Equals("SequenceNumber", StringComparison.OrdinalIgnoreCase) ||
                            valueName.Equals("Version", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        string executablePath = valueName;
                        string executableName = Path.GetFileName(executablePath);
                        string lastRun = DecodeFileTime(value.ValueDataRaw);

                        using var command = new SQLiteCommand(@"INSERT INTO bam_results
                            (ArtifactType, ExecutableName, ExecutablePath, LastRunTime, UserSID, UserProfile,
                             SourceType, Potential_Activity, SourceHive, File, Label, Comment)
                            VALUES ('BAM/DAM', @ExecutableName, @ExecutablePath, @LastRunTime, @UserSID,
                             @UserProfile, @SourceType, 'Program Execution', @SourceHive, @File, '', '')",
                            connection,
                            transaction);
                        command.Parameters.AddWithValue("@ExecutableName", executableName);
                        command.Parameters.AddWithValue("@ExecutablePath", executablePath);
                        command.Parameters.AddWithValue("@LastRunTime", lastRun);
                        command.Parameters.AddWithValue("@UserSID", sid);
                        command.Parameters.AddWithValue("@UserProfile", sid);
                        command.Parameters.AddWithValue("@SourceType", sourceType);
                        command.Parameters.AddWithValue("@SourceHive", systemHivePath);
                        command.Parameters.AddWithValue("@File", Path.GetFileName(systemHivePath));
                        command.ExecuteNonQuery();
                        ArtifactProvenance.RecordKey(connection, transaction, "bam_results", systemHivePath, $@"{keyPath}\{sid}", sidKey.LastWriteTime);
                        inserted++;
                    }
                }
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"BAM/DAM: {inserted:N0} entries");

            return new BamDamParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"BAM/DAM parse error from {systemHivePath}: {ex}");
            return new BamDamParseResult(0);
        }
    }

    public static ServicesParseResult ParseServices(
        string systemHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(systemHivePath) ||
            !File.Exists(systemHivePath))
        {
            return new ServicesParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            string currentControlSet = GetCurrentControlSet(hive);
            string servicesPath = $@"{currentControlSet}\Services";
            var servicesKey = hive.GetKey(servicesPath);
            if (servicesKey?.SubKeys == null)
                return new ServicesParseResult(0);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var serviceStub in servicesKey.SubKeys)
            {
                string serviceName = serviceStub.KeyName ?? "";
                string serviceKeyPath = $@"{servicesPath}\{serviceName}";
                var serviceKey = hive.GetKey(serviceKeyPath);
                if (serviceKey?.Values == null)
                    continue;

                int startValue = IntValue(serviceKey, "Start", -1);
                int typeValue = IntValue(serviceKey, "Type", -1);
                int errorControl = IntValue(serviceKey, "ErrorControl", -1);
                byte[]? dependencies = serviceKey.Values.FirstOrDefault(v =>
                    string.Equals(v.ValueName, "DependOnService", StringComparison.OrdinalIgnoreCase))?.ValueDataRaw;
                string dependsOn = dependencies == null ? "" : string.Join("; ",
                    System.Text.Encoding.Unicode.GetString(dependencies).Split('\0', StringSplitOptions.RemoveEmptyEntries));
                string serviceDll = "";
                var parametersKey = hive.GetKey($@"{serviceKeyPath}\Parameters");
                if (parametersKey?.Values != null)
                    serviceDll = Value(parametersKey, "ServiceDll");

                bool driver = typeValue > 0 && (typeValue & 0x0F) != 0;
                string artifactType = typeValue <= 0 ? "Services registry key" : driver ? "Driver" : "Service";
                string activity = typeValue <= 0 ? "Services registry configuration; Type value is absent or zero"
                    : driver ? "Driver registration/configuration; not proof it was loaded"
                    : "Windows service registration/configuration; not proof it was running";

                using var command = new SQLiteCommand(@"INSERT INTO services_results
                    (ArtifactType, Name, DisplayName, Description, ImagePath, ServiceDll, StartType,
                     StartValue, ServiceType, TypeValue, ObjectName, ErrorControl, Group_, DependsOn,
                     RegistryKey, HivePath, Potential_Activity, File, Label, Comment)
                    VALUES (@ArtifactType, @Name, @DisplayName, @Description, @ImagePath, @ServiceDll,
                     @StartType, @StartValue, @ServiceType, @TypeValue, @ObjectName, @ErrorControl,
                     @Group, @DependsOn, @RegistryKey, @HivePath, @PotentialActivity, @File, '', '')",
                    connection,
                    transaction);
                command.Parameters.AddWithValue("@Name", serviceName);
                command.Parameters.AddWithValue("@ArtifactType", artifactType);
                command.Parameters.AddWithValue("@DisplayName", Value(serviceKey, "DisplayName"));
                command.Parameters.AddWithValue("@Description", Value(serviceKey, "Description"));
                command.Parameters.AddWithValue("@ImagePath", Value(serviceKey, "ImagePath"));
                command.Parameters.AddWithValue("@ServiceDll", serviceDll);
                command.Parameters.AddWithValue("@StartType", DecodeStart(startValue));
                command.Parameters.AddWithValue("@StartValue", startValue);
                command.Parameters.AddWithValue("@ServiceType", DecodeType(typeValue));
                command.Parameters.AddWithValue("@TypeValue", typeValue);
                command.Parameters.AddWithValue("@ObjectName", Value(serviceKey, "ObjectName"));
                command.Parameters.AddWithValue("@ErrorControl", errorControl);
                command.Parameters.AddWithValue("@Group", Value(serviceKey, "Group"));
                command.Parameters.AddWithValue("@DependsOn", dependsOn);
                command.Parameters.AddWithValue("@RegistryKey", serviceKeyPath);
                command.Parameters.AddWithValue("@HivePath", systemHivePath);
                command.Parameters.AddWithValue("@PotentialActivity", activity);
                command.Parameters.AddWithValue("@File", Path.GetFileName(systemHivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "services_results", systemHivePath, serviceKeyPath, serviceKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Services/Drivers: {inserted:N0} entries");

            return new ServicesParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Services parse error from {systemHivePath}: {ex}");
            return new ServicesParseResult(0);
        }
    }

    public static NetworkInterfacesParseResult ParseNetworkInterfaces(
        string systemHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(systemHivePath) ||
            !File.Exists(systemHivePath))
        {
            return new NetworkInterfacesParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            string currentControlSet = GetCurrentControlSet(hive);
            string interfacesPath = $@"{currentControlSet}\Services\Tcpip\Parameters\Interfaces";
            var interfacesKey = hive.GetKey(interfacesPath);
            if (interfacesKey?.SubKeys == null)
                return new NetworkInterfacesParseResult(0);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var interfaceStub in interfacesKey.SubKeys)
            {
                string guid = interfaceStub.KeyName ?? "";
                if (string.IsNullOrWhiteSpace(guid))
                    continue;

                string interfaceKeyPath = $@"{interfacesPath}\{guid}";
                var interfaceKey = hive.GetKey(interfaceKeyPath);
                if (interfaceKey?.Values == null)
                    continue;

                int enableDhcp = IntValue(interfaceKey, "EnableDHCP", 0);
                string ipAddress = NormalizeMultiString(Value(interfaceKey, "IPAddress"));
                string subnetMask = NormalizeMultiString(Value(interfaceKey, "SubnetMask"));
                string defaultGateway = NormalizeMultiString(Value(interfaceKey, "DefaultGateway"));
                string dhcpIpAddress = Value(interfaceKey, "DhcpIPAddress");
                string dhcpSubnetMask = Value(interfaceKey, "DhcpSubnetMask");
                string dhcpDefaultGateway = NormalizeMultiString(Value(interfaceKey, "DhcpDefaultGateway"));
                string nameServer = Value(interfaceKey, "NameServer");
                string dhcpNameServer = Value(interfaceKey, "DhcpNameServer");
                string domain = Value(interfaceKey, "Domain");
                string dhcpDomain = Value(interfaceKey, "DhcpDomain");
                string dhcpServer = Value(interfaceKey, "DhcpServer");

                bool hasAny = !string.IsNullOrWhiteSpace(ipAddress) ||
                    !string.IsNullOrWhiteSpace(dhcpIpAddress) ||
                    !string.IsNullOrWhiteSpace(defaultGateway) ||
                    !string.IsNullOrWhiteSpace(dhcpDefaultGateway) ||
                    !string.IsNullOrWhiteSpace(nameServer) ||
                    !string.IsNullOrWhiteSpace(dhcpNameServer) ||
                    !string.IsNullOrWhiteSpace(dhcpServer) ||
                    !string.IsNullOrWhiteSpace(domain) ||
                    !string.IsNullOrWhiteSpace(dhcpDomain);
                if (!hasAny)
                    continue;

                using var command = new SQLiteCommand(@"INSERT INTO network_interfaces_results
                    (ArtifactType, InterfaceGuid, InterfaceDescription, EnableDHCP, ConnectionType,
                     IPAddress, SubnetMask, DefaultGateway, DhcpIPAddress, DhcpSubnetMask,
                     DhcpDefaultGateway, NameServer, DhcpNameServer, Domain, DhcpDomain,
                     DhcpServer, LeaseObtainedTime, LeaseTerminatesTime, RegistryKey, HivePath,
                     Potential_Activity, File, Label, Comment)
                    VALUES ('Network Interface', @InterfaceGuid, @InterfaceDescription, @EnableDHCP,
                     @ConnectionType, @IPAddress, @SubnetMask, @DefaultGateway, @DhcpIPAddress,
                     @DhcpSubnetMask, @DhcpDefaultGateway, @NameServer, @DhcpNameServer, @Domain,
                     @DhcpDomain, @DhcpServer, @LeaseObtainedTime, @LeaseTerminatesTime,
                     @RegistryKey, @HivePath, 'Network Configuration', @File, '', '')",
                    connection,
                    transaction);
                command.Parameters.AddWithValue("@InterfaceGuid", guid);
                command.Parameters.AddWithValue("@InterfaceDescription", Value(interfaceKey, "InterfaceDescription"));
                command.Parameters.AddWithValue("@EnableDHCP", enableDhcp);
                command.Parameters.AddWithValue("@ConnectionType", enableDhcp == 1 ? "DHCP" : "Static");
                command.Parameters.AddWithValue("@IPAddress", ipAddress);
                command.Parameters.AddWithValue("@SubnetMask", subnetMask);
                command.Parameters.AddWithValue("@DefaultGateway", defaultGateway);
                command.Parameters.AddWithValue("@DhcpIPAddress", dhcpIpAddress);
                command.Parameters.AddWithValue("@DhcpSubnetMask", dhcpSubnetMask);
                command.Parameters.AddWithValue("@DhcpDefaultGateway", dhcpDefaultGateway);
                command.Parameters.AddWithValue("@NameServer", nameServer);
                command.Parameters.AddWithValue("@DhcpNameServer", dhcpNameServer);
                command.Parameters.AddWithValue("@Domain", domain);
                command.Parameters.AddWithValue("@DhcpDomain", dhcpDomain);
                command.Parameters.AddWithValue("@DhcpServer", dhcpServer);
                command.Parameters.AddWithValue("@LeaseObtainedTime", UnixTimeToString(Value(interfaceKey, "LeaseObtainedTime")));
                command.Parameters.AddWithValue("@LeaseTerminatesTime", UnixTimeToString(Value(interfaceKey, "LeaseTerminatesTime")));
                command.Parameters.AddWithValue("@RegistryKey", interfaceKeyPath);
                command.Parameters.AddWithValue("@HivePath", systemHivePath);
                command.Parameters.AddWithValue("@File", Path.GetFileName(systemHivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "network_interfaces_results", systemHivePath, interfaceKeyPath, interfaceKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Network Interfaces: {inserted:N0} entries");

            return new NetworkInterfacesParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Network Interfaces parse error from {systemHivePath}: {ex}");
            return new NetworkInterfacesParseResult(0);
        }
    }

    public static SystemInfoParseResult ParseSystemInfoFromSystem(
        string systemHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(systemHivePath) ||
            !File.Exists(systemHivePath))
        {
            return new SystemInfoParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = 0;
            string currentControlSet = GetCurrentControlSet(hive);
            inserted += InsertSystemInfo(connection, transaction, systemHivePath, "Select", "OS", "ActiveControlSet", currentControlSet, hive.GetKey("Select")?.LastWriteTime);

            string computerNameKey = $@"{currentControlSet}\Control\ComputerName\ComputerName";
            var computerName = hive.GetKey(computerNameKey);
            inserted += InsertSystemInfo(connection, transaction, systemHivePath, computerNameKey, "Computer", "ComputerName", Value(computerName, "ComputerName"), computerName?.LastWriteTime);

            string activeComputerNameKey = $@"{currentControlSet}\Control\ComputerName\ActiveComputerName";
            var activeComputerName = hive.GetKey(activeComputerNameKey);
            inserted += InsertSystemInfo(connection, transaction, systemHivePath, activeComputerNameKey, "Computer", "ActiveComputerName", Value(activeComputerName, "ComputerName"), activeComputerName?.LastWriteTime);

            string timeZoneKeyPath = $@"{currentControlSet}\Control\TimeZoneInformation";
            var timeZone = hive.GetKey(timeZoneKeyPath);
            foreach (string valueName in new[] { "TimeZoneKeyName", "StandardName", "DaylightName", "Bias", "ActiveTimeBias", "StandardBias", "DaylightBias" })
            {
                string raw = Value(timeZone, valueName), interpreted = raw;
                byte[]? bytes = RawValue(timeZone, valueName);
                if (valueName.EndsWith("Bias", StringComparison.Ordinal) && bytes?.Length == 4 &&
                    uint.TryParse(raw, out uint number) && number == BitConverter.ToUInt32(bytes, 0))
                    interpreted = BitConverter.ToInt32(bytes, 0).ToString(System.Globalization.CultureInfo.InvariantCulture);
                inserted += InsertSystemInfo(connection, transaction, systemHivePath, timeZoneKeyPath, "TimeZone", valueName,
                    interpreted, timeZone?.LastWriteTime, interpreted == raw ? null : raw);
            }

            string windowsKeyPath = $@"{currentControlSet}\Control\Windows";
            var windowsKey = hive.GetKey(windowsKeyPath);
            inserted += InsertSystemInfo(connection, transaction, systemHivePath, windowsKeyPath, "Shutdown", "ShutdownTime", DecodeFileTime(RawValue(windowsKey, "ShutdownTime")), windowsKey?.LastWriteTime);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"System Information (SYSTEM): {inserted:N0} properties");

            return new SystemInfoParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"System Information SYSTEM parse error from {systemHivePath}: {ex}");
            return new SystemInfoParseResult(0);
        }
    }

    public static FirewallRulesParseResult ParseFirewallRules(
        string systemHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(systemHivePath) ||
            !File.Exists(systemHivePath))
        {
            return new FirewallRulesParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            string currentControlSet = GetCurrentControlSet(hive);
            string rulesPath = $@"{currentControlSet}\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
            var rulesKey = hive.GetKey(rulesPath);
            if (rulesKey?.Values == null)
                return new FirewallRulesParseResult(0);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;
            int blockRules = 0;

            foreach (var value in rulesKey.Values)
            {
                string ruleId = value.ValueName ?? "";
                string rawRule = value.ValueData ?? "";
                if (string.IsNullOrWhiteSpace(rawRule) || ruleId.Equals("(default)", StringComparison.OrdinalIgnoreCase))
                    continue;

                var fields = ParseFirewallRule(rawRule, out string schemaVersion);
                string field(string key) => fields.TryGetValue(key, out string? found) ? found : "";

                string action = field("Action");
                if (action.Equals("Block", StringComparison.OrdinalIgnoreCase))
                    blockRules++;

                var localAddresses = new List<string>();
                if (!string.IsNullOrWhiteSpace(field("LA4"))) localAddresses.Add(field("LA4"));
                if (!string.IsNullOrWhiteSpace(field("LA6"))) localAddresses.Add(field("LA6"));

                var remoteAddresses = new List<string>();
                if (!string.IsNullOrWhiteSpace(field("RA4"))) remoteAddresses.Add(field("RA4"));
                if (!string.IsNullOrWhiteSpace(field("RA6"))) remoteAddresses.Add(field("RA6"));

                string direction = field("Dir") switch
                {
                    "In" => "Inbound",
                    "Out" => "Outbound",
                    var other => other
                };

                using var command = new SQLiteCommand(@"INSERT INTO firewall_rules_results
                    (ArtifactType, RuleId, RuleName, Description, Action, Active, Direction,
                     Protocol, LocalPort, RemotePort, ApplicationPath, ServiceName,
                     LocalAddress, RemoteAddress, Profile, SchemaVersion, RawRule,
                     RegistryKey, HivePath, Potential_Activity, File, Label, Comment)
                    VALUES ('Firewall Rule', @RuleId, @RuleName, @Description, @Action, @Active,
                     @Direction, @Protocol, @LocalPort, @RemotePort, @ApplicationPath, @ServiceName,
                     @LocalAddress, @RemoteAddress, @Profile, @SchemaVersion, @RawRule,
                     @RegistryKey, @HivePath, @PotentialActivity, @File, '', '')",
                    connection,
                    transaction);
                command.Parameters.AddWithValue("@RuleId", ruleId);
                command.Parameters.AddWithValue("@RuleName", field("Name"));
                command.Parameters.AddWithValue("@Description", field("Desc"));
                command.Parameters.AddWithValue("@Action", action);
                command.Parameters.AddWithValue("@Active", field("Active"));
                command.Parameters.AddWithValue("@Direction", direction);
                command.Parameters.AddWithValue("@Protocol", DecodeFirewallProtocol(field("Protocol")));
                command.Parameters.AddWithValue("@LocalPort", field("LPort"));
                command.Parameters.AddWithValue("@RemotePort", field("RPort"));
                command.Parameters.AddWithValue("@ApplicationPath", field("App"));
                command.Parameters.AddWithValue("@ServiceName", field("Svc"));
                command.Parameters.AddWithValue("@LocalAddress", string.Join("; ", localAddresses));
                command.Parameters.AddWithValue("@RemoteAddress", string.Join("; ", remoteAddresses));
                command.Parameters.AddWithValue("@Profile", string.IsNullOrWhiteSpace(field("Profile")) ? "All" : field("Profile"));
                command.Parameters.AddWithValue("@SchemaVersion", schemaVersion);
                command.Parameters.AddWithValue("@RawRule", rawRule);
                command.Parameters.AddWithValue("@RegistryKey", rulesPath);
                command.Parameters.AddWithValue("@HivePath", systemHivePath);
                command.Parameters.AddWithValue("@PotentialActivity", action.Equals("Block", StringComparison.OrdinalIgnoreCase) ? "Firewall Block Rule" : "Firewall Rule");
                command.Parameters.AddWithValue("@File", Path.GetFileName(systemHivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "firewall_rules_results", systemHivePath, rulesPath, rulesKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
            {
                string tail = blockRules > 0 ? $" ({blockRules:N0} block)" : "";
                progress?.Report($"Firewall Rules: {inserted:N0} entries{tail}");
            }

            return new FirewallRulesParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Firewall Rules parse error from {systemHivePath}: {ex}");
            return new FirewallRulesParseResult(0);
        }
    }

    public static ShimCacheParseResult ParseShimCache(
        string systemHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(systemHivePath) ||
            !File.Exists(systemHivePath))
        {
            return new ShimCacheParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            var controlSets = new SortedSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ControlSet001",
                "ControlSet002",
                GetCurrentControlSet(hive)
            };

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (string controlSet in controlSets)
            {
                string keyPath = $@"{controlSet}\Control\Session Manager\AppCompatCache";
                var key = hive.GetKey(keyPath);
                byte[]? raw = RawValue(key, "AppCompatCache");
                if (raw == null || raw.Length == 0)
                    continue;

                var cache = new AppCompatCache.AppCompatCache(raw, 1, true);
                foreach (var cacheSet in cache.Caches)
                {
                    foreach (var entry in cacheSet.Entries)
                    {
                        string lastModified = entry.LastModifiedTimeUTC.HasValue
                            ? entry.LastModifiedTimeUTC.Value.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
                            : "";
                        string executed = entry.Executed.ToString();
                        string potentialActivity = executed.IndexOf("Yes", StringComparison.OrdinalIgnoreCase) >= 0
                            ? "Confirmed Application Execution"
                            : "Executable Present on System";

                        using var command = new SQLiteCommand(@"INSERT INTO shimcache_results
                            (ArtifactType, Path, LastModified, Executed, FileSize, SequenceNumber,
                             ControlSet, HivePath, Potential_Activity, File, Label, Comment)
                            VALUES ('ShimCache', @Path, @LastModified, @Executed, @FileSize,
                             @SequenceNumber, @ControlSet, @HivePath, @PotentialActivity, @File, '', '')",
                            connection,
                            transaction);
                        command.Parameters.AddWithValue("@Path", entry.Path ?? "");
                        command.Parameters.AddWithValue("@LastModified", string.IsNullOrWhiteSpace(lastModified) ? DBNull.Value : lastModified);
                        command.Parameters.AddWithValue("@Executed", executed);
                        command.Parameters.AddWithValue("@FileSize", entry.CacheEntrySize);
                        command.Parameters.AddWithValue("@SequenceNumber", entry.CacheEntryPosition);
                        command.Parameters.AddWithValue("@ControlSet", controlSet);
                        command.Parameters.AddWithValue("@HivePath", systemHivePath);
                        command.Parameters.AddWithValue("@PotentialActivity", potentialActivity);
                        command.Parameters.AddWithValue("@File", Path.GetFileName(systemHivePath));
                        command.ExecuteNonQuery();
                        ArtifactProvenance.RecordKey(connection, transaction, "shimcache_results", systemHivePath, keyPath, key.LastWriteTime);
                        inserted++;
                    }
                }
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"ShimCache: {inserted:N0} entries");

            return new ShimCacheParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"ShimCache parse error from {systemHivePath}: {ex}");
            return new ShimCacheParseResult(0);
        }
    }

    private static Dictionary<string, string> ParseFirewallRule(string rawRule, out string schemaVersion)
    {
        schemaVersion = "";
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string part in rawRule.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            int equalsIndex = part.IndexOf('=');
            if (equalsIndex < 0)
            {
                if (schemaVersion.Length == 0 && part.StartsWith("v", StringComparison.OrdinalIgnoreCase))
                    schemaVersion = part;

                continue;
            }

            string key = part[..equalsIndex];
            string value = part[(equalsIndex + 1)..];
            fields[key] = fields.TryGetValue(key, out string? previous) ? previous + "; " + value : value;
        }

        return fields;
    }

    private static string DecodeFirewallProtocol(string protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol))
            return "";

        return protocol switch
        {
            "6" => "TCP(6)",
            "17" => "UDP(17)",
            "1" => "ICMPv4(1)",
            "58" => "ICMPv6(58)",
            "47" => "GRE(47)",
            "50" => "ESP(50)",
            "51" => "AH(51)",
            "*" => "Any",
            _ => $"Other({protocol})"
        };
    }

    private static int InsertSystemInfo(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string hivePath,
        string registryKey,
        string category,
        string propertyKey,
        string propertyValue,
        DateTimeOffset? keyLastWrite,
        string? rawPropertyValue = null)
    {
        if (string.IsNullOrWhiteSpace(propertyValue))
            return 0;

        using var command = new SQLiteCommand(@"INSERT INTO system_info_results
            (ArtifactType, PropertyKey, PropertyValue, RawPropertyValue, Category, HivePath, RegistryKey,
             Potential_Activity, File, Label, Comment)
            VALUES ('System Info', @PropertyKey, @PropertyValue, @RawPropertyValue, @Category, @HivePath,
             @RegistryKey, 'System Configuration', @File, '', '')",
            connection,
            transaction);
        command.Parameters.AddWithValue("@PropertyKey", propertyKey);
        command.Parameters.AddWithValue("@PropertyValue", propertyValue);
        command.Parameters.AddWithValue("@RawPropertyValue", (object?)rawPropertyValue ?? DBNull.Value);
        command.Parameters.AddWithValue("@Category", category);
        command.Parameters.AddWithValue("@HivePath", hivePath);
        command.Parameters.AddWithValue("@RegistryKey", registryKey);
        command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
        command.ExecuteNonQuery();
        ArtifactProvenance.RecordKey(connection, transaction, "system_info_results", hivePath, registryKey, keyLastWrite);
        return 1;
    }

    private static string DecodeFileTime(byte[]? data)
    {
        if (data == null || data.Length < 8)
            return string.Empty;

        try
        {
            long fileTime = BitConverter.ToInt64(data, 0);
            return fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime).ToString("O", System.Globalization.CultureInfo.InvariantCulture) : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static byte[]? RawValue(dynamic? key, string valueName)
    {
        if (key?.Values == null)
            return null;

        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, valueName, StringComparison.OrdinalIgnoreCase))
                return value.ValueDataRaw;
        }

        return null;
    }

    private static string GetCurrentControlSet(RegistryHiveOnDemand hive)
    {
        var selectKey = hive.GetKey("Select");
        int current = IntValue(selectKey, "Current", 1);
        return $"ControlSet{current:D3}";
    }

    private static string DecodeStart(int value)
    {
        return value switch
        {
            0 => "Boot",
            1 => "System",
            2 => "Automatic",
            3 => "Manual",
            4 => "Disabled",
            _ => $"Unknown({value})"
        };
    }

    private static string DecodeType(int value)
    {
        if (value < 0) return "Unknown";
        var parts = new List<string>();
        if ((value & 0x01) != 0) parts.Add("KernelDriver");
        if ((value & 0x02) != 0) parts.Add("FileSystemDriver");
        if ((value & 0x04) != 0) parts.Add("Adapter");
        if ((value & 0x08) != 0) parts.Add("RecognizerDriver");
        if ((value & 0x10) != 0) parts.Add("Win32OwnProcess");
        if ((value & 0x20) != 0) parts.Add("Win32SharedProcess");
        if ((value & 0x100) != 0) parts.Add("Interactive");
        return parts.Count == 0 ? $"Unknown(0x{value:X})" : string.Join("+", parts);
    }

    private static string NormalizeMultiString(string value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? ""
            : string.Join("; ", value.Replace("\r\n", ";")
                .Replace('\0', ';')
                .Replace('\n', ';')
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    private static string UnixTimeToString(string raw)
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

    private static string Value(dynamic? key, string valueName)
    {
        if (key?.Values == null)
            return "";

        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, valueName, StringComparison.OrdinalIgnoreCase))
                return value.ValueData ?? "";
        }

        return "";
    }

    private static int IntValue(dynamic? key, string valueName, int defaultValue)
    {
        string raw = Value(key, valueName);
        return int.TryParse(raw, out int value) ? value : defaultValue;
    }
}
