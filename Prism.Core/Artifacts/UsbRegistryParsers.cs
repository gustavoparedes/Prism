using Registry;
using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record UsbStorParseResult(int Inserted);

public sealed record MountPoints2ParseResult(int Inserted);

public static class UsbRegistryParsers
{
    public static void CreateTable(SQLiteConnection connection)
    {
        using var command = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS usbstor_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            RecordType TEXT,
            DeviceType TEXT,
            Vendor TEXT,
            Product TEXT,
            Revision TEXT,
            SerialNumber TEXT,
            FriendlyName TEXT,
            DeviceDesc TEXT,
            ContainerID TEXT,
            HardwareID TEXT,
            Manufacturer TEXT,
            InstallDate TEXT,
            FirstInstall TEXT,
            LastArrival TEXT,
            LastRemoval TEXT,
            KeyLastWrite TEXT,
            VolumeGUID TEXT,
            VolumeLabel TEXT,
            UserProfile TEXT,
            Potential_Activity TEXT,
            SourceHive TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        command.ExecuteNonQuery();
        ArtifactSchema.EnsureColumns(connection, "usbstor_results", ("InstanceId", "TEXT"), ("DeviceClassId", "TEXT"));
    }

    public static UsbStorParseResult ParseUsbStor(
        string systemHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(systemHivePath) ||
            !File.Exists(systemHivePath))
        {
            return new UsbStorParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            var select = hive.GetKey("Select");
            string current = select == null ? "1" : Value(select, "Current");
            string controlSet = $"ControlSet{(int.TryParse(current, out int selected) ? selected : 1):D3}";
            string rootPath = controlSet + @"\Enum\USBSTOR";
            var usbstorKey = hive.GetKey(rootPath);
            if (usbstorKey?.SubKeys == null)
                return new UsbStorParseResult(0);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTable(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var deviceTypeStub in usbstorKey.SubKeys)
            {
                string deviceTypeName = deviceTypeStub.KeyName ?? "";
                ParseUsbDeviceType(deviceTypeName, out string deviceType, out string vendor, out string product, out string revision);
                var deviceTypeKey = hive.GetKey($@"{rootPath}\{deviceTypeName}");
                if (deviceTypeKey?.SubKeys == null)
                    continue;

                foreach (var serialStub in deviceTypeKey.SubKeys)
                {
                    var serialKey = hive.GetKey($@"{rootPath}\{deviceTypeName}\{serialStub.KeyName}");
                    if (serialKey == null)
                        continue;

                    string rawSerial = serialKey.KeyName ?? "";
                    string serialNumber = rawSerial.Contains('&') ? rawSerial[..rawSerial.IndexOf('&')] : rawSerial;
                    string friendlyName = Value(serialKey, "FriendlyName");
                    string deviceDesc = Value(serialKey, "DeviceDesc");
                    string containerId = Value(serialKey, "ContainerID");
                    string hardwareId = Value(serialKey, "HardwareID");
                    string manufacturer = Value(serialKey, "Mfg");
                    string keyLastWrite = FormatLastWrite(serialKey.LastWriteTime);
                    string propertiesBase = $@"{rootPath}\{deviceTypeName}\{rawSerial}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}";
                    string installDate = ReadUsbFileTime(hive, propertiesBase + @"\0064");
                    string firstInstall = ReadUsbFileTime(hive, propertiesBase + @"\0065");
                    string lastArrival = ReadUsbFileTime(hive, propertiesBase + @"\0066");
                    string lastRemoval = ReadUsbFileTime(hive, propertiesBase + @"\0067");

                    bool syntheticSerial = rawSerial.Contains('&');
                    string potentialActivity = !string.IsNullOrWhiteSpace(lastRemoval)
                        ? "USB Storage Device Removal"
                        : !string.IsNullOrWhiteSpace(firstInstall) && firstInstall == lastArrival
                            ? "USB Storage Device First Connection"
                            : "USB Storage Device Connected";
                    if (syntheticSerial)
                        potentialActivity += " (Non-Unique Serial)";

                    InsertRow(
                        connection,
                        transaction,
                        "USBSTOR",
                        deviceType,
                        vendor,
                        product,
                        revision,
                        serialNumber,
                        friendlyName,
                        deviceDesc,
                        containerId,
                        hardwareId,
                        manufacturer,
                        firstInstall,
                        lastArrival,
                        lastRemoval,
                        keyLastWrite,
                        "",
                        "",
                        "",
                        potentialActivity,
                        systemHivePath, installDate);
                    using var identity = new SQLiteCommand(@"UPDATE usbstor_results SET InstanceId=@instance,
                        DeviceClassId=@class WHERE id=(SELECT MAX(id) FROM usbstor_results)", connection, transaction);
                    identity.Parameters.AddWithValue("@instance", rawSerial);
                    identity.Parameters.AddWithValue("@class", deviceTypeName);
                    identity.ExecuteNonQuery();
                    ArtifactProvenance.RecordKey(connection, transaction, "usbstor_results", systemHivePath,
                        $@"{rootPath}\{deviceTypeName}\{rawSerial}", serialKey.LastWriteTime);
                    inserted++;
                }
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"USBSTOR: {inserted:N0} entries");

            return new UsbStorParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"USBSTOR parse error from {systemHivePath}: {ex}");
            return new UsbStorParseResult(0);
        }
    }

    public static MountPoints2ParseResult ParseMountPoints2(
        string ntuserPath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(ntuserPath) ||
            !File.Exists(ntuserPath))
        {
            return new MountPoints2ParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(ntuserPath);
            var mountPointsKey = hive.GetKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2");
            if (mountPointsKey?.SubKeys == null)
                return new MountPoints2ParseResult(0);

            string userProfile = InferUserProfileFromHivePath(ntuserPath);
            var mountedDevices = LoadMountedDevices(FindSystemHiveFromNtuser(ntuserPath));

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTable(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var mountKey in mountPointsKey.SubKeys)
            {
                string keyName = mountKey.KeyName ?? "";
                bool isGuid = keyName.StartsWith("{", StringComparison.Ordinal);
                bool isNetwork = keyName.StartsWith("#", StringComparison.Ordinal);
                bool isDriveLetter = keyName.Length == 2 && keyName[1] == ':';
                if (!isGuid && !isNetwork && !isDriveLetter)
                    continue;

                string keyLastWrite = FormatLastWrite(mountKey.LastWriteTime);
                var fullMountKey = hive.GetKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{keyName}");
                string volumeLabel = fullMountKey != null
                    ? Value(fullMountKey, "_LabelFromReg")
                    : "";
                if (string.IsNullOrWhiteSpace(volumeLabel) && fullMountKey != null)
                    volumeLabel = Value(fullMountKey, "_LabelFromDesktop");

                string volumeGuid = "";
                string driveLetter = "";
                string devicePath = "";
                string deviceType = "";
                string vendor = "";
                string product = "";
                string revision = "";
                string serialNumber = "";
                string friendlyName = "";
                string potentialActivity = "Volume Mounted by User";

                if (isGuid)
                {
                    volumeGuid = keyName;
                    mountedDevices.GuidToDevicePath.TryGetValue(keyName, out devicePath!);
                    mountedDevices.GuidToDriveLetter.TryGetValue(keyName, out driveLetter!);
                }
                else if (isNetwork)
                {
                    friendlyName = keyName.Replace('#', '\\');
                    deviceType = "Network";
                    potentialActivity = "Network Share Mounted";
                }
                else if (isDriveLetter)
                {
                    driveLetter = keyName;
                    mountedDevices.DriveToGuid.TryGetValue(keyName, out volumeGuid!);
                    if (!string.IsNullOrWhiteSpace(volumeGuid))
                        mountedDevices.GuidToDevicePath.TryGetValue(volumeGuid, out devicePath!);
                }

                if (!string.IsNullOrWhiteSpace(devicePath))
                    EnrichMountedDevicePath(devicePath, ref deviceType, ref vendor, ref product, ref revision, ref serialNumber, ref friendlyName, ref potentialActivity);

                if (string.IsNullOrWhiteSpace(friendlyName))
                {
                    if (!string.IsNullOrWhiteSpace(volumeLabel))
                        friendlyName = volumeLabel;
                    else if (!string.IsNullOrWhiteSpace(driveLetter))
                        friendlyName = $"Volume ({driveLetter})";
                }

                InsertRow(
                    connection,
                    transaction,
                    "MountPoint",
                    deviceType,
                    vendor,
                    product,
                    revision,
                    serialNumber,
                    friendlyName,
                    devicePath,
                    "",
                    driveLetter,
                    "",
                    "",
                    "",
                    "",
                    keyLastWrite,
                    volumeGuid,
                    volumeLabel,
                    userProfile,
                    potentialActivity,
                    ntuserPath);
                ArtifactProvenance.RecordKey(connection,transaction,"usbstor_results",ntuserPath,
                    $@"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{keyName}",mountKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"MountPoints2 ({userProfile}): {inserted:N0} entries");

            return new MountPoints2ParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"MountPoints2 parse error from {ntuserPath}: {ex}");
            return new MountPoints2ParseResult(0);
        }
    }

    private static void InsertRow(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string recordType,
        string deviceType,
        string vendor,
        string product,
        string revision,
        string serialNumber,
        string friendlyName,
        string deviceDesc,
        string containerId,
        string hardwareId,
        string manufacturer,
        string firstInstall,
        string lastArrival,
        string lastRemoval,
        string keyLastWrite,
        string volumeGuid,
        string volumeLabel,
        string userProfile,
        string potentialActivity,
        string sourceHive,
        string installDate = "")
    {
        using var command = new SQLiteCommand(@"INSERT INTO usbstor_results
            (ArtifactType, RecordType, DeviceType, Vendor, Product, Revision, SerialNumber,
             FriendlyName, DeviceDesc, ContainerID, HardwareID, Manufacturer, FirstInstall,
             LastArrival, LastRemoval, KeyLastWrite, VolumeGUID, VolumeLabel, UserProfile,
             Potential_Activity, SourceHive, File, Label, Comment, InstallDate)
            VALUES ('USB Device', @RecordType, @DeviceType, @Vendor, @Product, @Revision,
             @SerialNumber, @FriendlyName, @DeviceDesc, @ContainerID, @HardwareID, @Manufacturer,
             @FirstInstall, @LastArrival, @LastRemoval, @KeyLastWrite, @VolumeGUID, @VolumeLabel,
             @UserProfile, @PotentialActivity, @SourceHive, @File, '', '', @InstallDate)", connection, transaction);
        command.Parameters.AddWithValue("@InstallDate", installDate);
        command.Parameters.AddWithValue("@RecordType", recordType);
        command.Parameters.AddWithValue("@DeviceType", deviceType);
        command.Parameters.AddWithValue("@Vendor", vendor);
        command.Parameters.AddWithValue("@Product", product);
        command.Parameters.AddWithValue("@Revision", revision);
        command.Parameters.AddWithValue("@SerialNumber", serialNumber);
        command.Parameters.AddWithValue("@FriendlyName", friendlyName);
        command.Parameters.AddWithValue("@DeviceDesc", deviceDesc);
        command.Parameters.AddWithValue("@ContainerID", containerId);
        command.Parameters.AddWithValue("@HardwareID", hardwareId);
        command.Parameters.AddWithValue("@Manufacturer", manufacturer);
        command.Parameters.AddWithValue("@FirstInstall", firstInstall);
        command.Parameters.AddWithValue("@LastArrival", lastArrival);
        command.Parameters.AddWithValue("@LastRemoval", lastRemoval);
        command.Parameters.AddWithValue("@KeyLastWrite", keyLastWrite);
        command.Parameters.AddWithValue("@VolumeGUID", volumeGuid);
        command.Parameters.AddWithValue("@VolumeLabel", volumeLabel);
        command.Parameters.AddWithValue("@UserProfile", userProfile);
        command.Parameters.AddWithValue("@PotentialActivity", potentialActivity);
        command.Parameters.AddWithValue("@SourceHive", sourceHive);
        command.Parameters.AddWithValue("@File", Path.GetFileName(sourceHive));
        command.ExecuteNonQuery();
    }

    private static void ParseUsbDeviceType(string deviceTypeName, out string deviceType, out string vendor, out string product, out string revision)
    {
        deviceType = "";
        vendor = "";
        product = "";
        revision = "";

        string[] parts = deviceTypeName.Split('&');
        if (parts.Length > 0)
            deviceType = parts[0];

        foreach (string part in parts)
        {
            if (part.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase))
                vendor = part[4..];
            else if (part.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase))
                product = part[5..];
            else if (part.StartsWith("Rev_", StringComparison.OrdinalIgnoreCase))
                revision = part[4..];
        }
    }

    private static string Value(dynamic key, string valueName)
    {
        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, valueName, StringComparison.OrdinalIgnoreCase))
                return value.ValueData ?? "";
        }

        return "";
    }

    private static string ReadUsbFileTime(RegistryHiveOnDemand hive, string fullKeyPath)
    {
        try
        {
            var key = hive.GetKey(fullKeyPath);
            var value = key?.Values?.FirstOrDefault();
            byte[]? bytes = value?.ValueDataRaw;
            if (bytes == null || bytes.Length < 8)
                bytes = ParseHexBytes(value?.ValueData);
            if (bytes == null || bytes.Length < 8)
                return "";

            long fileTime = BitConverter.ToInt64(bytes, 0);
            return fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime).ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
        }
        catch
        {
            return "";
        }
    }

    private static byte[]? ParseHexBytes(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var bytes = new List<byte>();
        foreach (string token in value.Split(new[] { ' ', '-', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.Length == 2 && byte.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                bytes.Add(b);
        }

        return bytes.Count > 0 ? bytes.ToArray() : null;
    }

    private static string FormatLastWrite(DateTimeOffset? lastWrite)
    {
        return lastWrite.HasValue ? lastWrite.Value.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
    }

    private sealed record MountedDevicesLookup(
        Dictionary<string, string> GuidToDevicePath,
        Dictionary<string, string> GuidToDriveLetter,
        Dictionary<string, string> DriveToGuid);

    private static MountedDevicesLookup LoadMountedDevices(string? systemHivePath)
    {
        var guidToDevicePath = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var guidToDriveLetter = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var driveToGuid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var driveToDevicePath = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(systemHivePath) || !File.Exists(systemHivePath))
            return new MountedDevicesLookup(guidToDevicePath, guidToDriveLetter, driveToGuid);

        try
        {
            var hive = new RegistryHiveOnDemand(systemHivePath);
            var mountedDevices = hive.GetKey("MountedDevices");
            if (mountedDevices?.Values == null)
                return new MountedDevicesLookup(guidToDevicePath, guidToDriveLetter, driveToGuid);

            foreach (var value in mountedDevices.Values)
            {
                byte[] data = value.ValueDataRaw;
                if (data == null || data.Length <= 24)
                    continue;

                string devicePath = Encoding.Unicode.GetString(data).TrimEnd('\0');
                string valueName = value.ValueName ?? "";
                if (valueName.StartsWith(@"\??\Volume{", StringComparison.OrdinalIgnoreCase))
                {
                    string guid = valueName[@"\??\Volume".Length..];
                    guidToDevicePath[guid] = devicePath;
                }
                else if (valueName.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase))
                {
                    string drive = valueName[@"\DosDevices\".Length..];
                    driveToDevicePath[drive] = devicePath;
                }
            }

            foreach (var guid in guidToDevicePath)
            {
                foreach (var drive in driveToDevicePath)
                {
                    if (!string.Equals(guid.Value, drive.Value, StringComparison.OrdinalIgnoreCase))
                        continue;

                    guidToDriveLetter[guid.Key] = drive.Key;
                    driveToGuid[drive.Key] = guid.Key;
                    break;
                }
            }
        }
        catch
        {
        }

        return new MountedDevicesLookup(guidToDevicePath, guidToDriveLetter, driveToGuid);
    }

    private static void EnrichMountedDevicePath(
        string devicePath,
        ref string deviceType,
        ref string vendor,
        ref string product,
        ref string revision,
        ref string serialNumber,
        ref string friendlyName,
        ref string potentialActivity)
    {
        if (devicePath.IndexOf("USBSTOR#", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            deviceType = "Removable";
            potentialActivity = "Removable Drive Mounted";
            int usbIndex = devicePath.IndexOf("USBSTOR#", StringComparison.OrdinalIgnoreCase) + "USBSTOR#".Length;
            string[] segments = devicePath[usbIndex..].Split('#');
            if (segments.Length >= 2)
            {
                string deviceId = segments[0];
                string serialRaw = segments[1];
                serialNumber = serialRaw.Contains('&') ? serialRaw[..serialRaw.IndexOf('&')] : serialRaw;
                foreach (string part in deviceId.Split('&'))
                {
                    if (part.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase))
                        vendor = part[4..].Replace('_', ' ').Trim();
                    else if (part.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase))
                        product = part[5..].Replace('_', ' ').Trim();
                    else if (part.StartsWith("Rev_", StringComparison.OrdinalIgnoreCase))
                        revision = part[4..].Trim();
                }
            }

            if (string.IsNullOrWhiteSpace(friendlyName))
                friendlyName = $"{vendor} {product}".Trim();
        }
        else if (devicePath.IndexOf("CdRom", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            deviceType = "CdRom";
            potentialActivity = "Optical Drive Mounted";
        }
        else if (devicePath.IndexOf("Floppy", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            deviceType = "Floppy";
        }
        else
        {
            deviceType = "Fixed";
        }
    }

    private static string? FindSystemHiveFromNtuser(string ntuserPath)
    {
        if(Acquisition.WindowsEvidenceContext.Current is { } catalog)return catalog.RelatedSystem(ntuserPath);
        try
        {
            string? root = Path.GetPathRoot(ntuserPath);
            if (!string.IsNullOrWhiteSpace(root))
            {
                string candidate = Path.Combine(root, @"Windows\System32\config\SYSTEM");
                if (File.Exists(candidate))
                    return candidate;
            }

            DirectoryInfo? current = Directory.GetParent(Path.GetDirectoryName(ntuserPath) ?? "");
            while (current != null)
            {
                string candidate = Path.Combine(current.FullName, @"Windows\System32\config\SYSTEM");
                if (File.Exists(candidate))
                    return candidate;
                current = current.Parent;
            }
        }
        catch
        {
        }

        return null;
    }

    private static string InferUserProfileFromHivePath(string hivePath)
    {
        if(Acquisition.WindowsEvidenceContext.Current is { } catalog)return catalog.UserName(hivePath);
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
}
