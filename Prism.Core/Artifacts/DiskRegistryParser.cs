using Registry;
using System.Data.SQLite;
using System.Text.Json;

namespace Prism.Core.Artifacts;

public static class DiskRegistryParser
{
    public static void CreateTable(SQLiteConnection db)
    {
        using var cmd = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS disk_devices_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ArtifactType TEXT, Model TEXT,
            DeviceInstanceId TEXT, Enumerator TEXT, FriendlyName TEXT, DeviceDescription TEXT,
            Manufacturer TEXT, HardwareIds TEXT, CompatibleIds TEXT, Service TEXT, ClassGuid TEXT,
            ContainerId TEXT, LocationInformation TEXT, LastWrite TEXT, RegistryKey TEXT, HivePath TEXT,
            RawValuesJson TEXT, Potential_Activity TEXT, File TEXT, Label TEXT, Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", db);
        cmd.ExecuteNonQuery();
    }

    public static int Parse(string source, string connectionString, IProgress<string>? progress = null)
    {
        var hive = new RegistryHiveOnDemand(source);
        string V(dynamic? key, string name)
        {
            if (key?.Values == null) return "";
            foreach (var value in key.Values)
                if (string.Equals((string?)value.ValueName, name, StringComparison.OrdinalIgnoreCase)) return value.ValueData ?? "";
            return "";
        }
        int current = int.TryParse(V(hive.GetKey("Select"), "Current"), out int number) ? number : 1;
        using var db = new SQLiteConnection(connectionString); db.Open(); CreateTable(db);
        using var tx = db.BeginTransaction(); int inserted = 0;
        foreach (string enumerator in new[] { "SCSI", "IDE", "STORAGE", "USBSTOR", "NVME" })
        {
            string root = $@"ControlSet{current:D3}\Enum\{enumerator}";
            var parent = hive.GetKey(root); if (parent?.SubKeys == null) continue;
            foreach (var device in parent.SubKeys)
            {
                var type = hive.GetKey(root + "\\" + device.KeyName); if (type?.SubKeys == null) continue;
                foreach (var instance in type.SubKeys)
                {
                    string path = root + "\\" + device.KeyName + "\\" + instance.KeyName;
                    var key = hive.GetKey(path); if (key == null) continue;
                    string guid = V(key, "ClassGUID"), className = V(key, "Class");
                    if (!guid.Equals("{4d36e967-e325-11ce-bfc1-08002be10318}", StringComparison.OrdinalIgnoreCase) &&
                        !className.Equals("DiskDrive", StringComparison.OrdinalIgnoreCase)) continue;
                    string friendly = V(key, "FriendlyName"), description = V(key, "DeviceDesc");

                    string model = friendly.Length > 0 ? friendly : description.StartsWith('@') ? "" : description;
                    var raw = key.Values.Select(v => new { Name = v.ValueName, Type = v.ValueType.ToString(),
                        Value = v.ValueData, RawBase64 = Convert.ToBase64String(v.ValueDataRaw ?? Array.Empty<byte>()) }).ToArray();
                    using var cmd = new SQLiteCommand(@"INSERT INTO disk_devices_results
                        (ArtifactType,Model,DeviceInstanceId,Enumerator,FriendlyName,DeviceDescription,Manufacturer,
                         HardwareIds,CompatibleIds,Service,ClassGuid,ContainerId,LocationInformation,LastWrite,
                         RegistryKey,HivePath,RawValuesJson,Potential_Activity,File,Label,Comment)
                        VALUES('Disk Device',@model,@instance,@enum,@friendly,@description,@manufacturer,@hardware,
                         @compatible,@service,@class,@container,@location,@last,@key,@source,@raw,
                         'The operating system registered a disk device; this does not establish when or by whom it was connected.',@file,'','')", db, tx);
                    foreach (var parameter in new Dictionary<string, object?> {
                        ["@model"]=model,["@instance"]=enumerator+"\\"+device.KeyName+"\\"+instance.KeyName,
                        ["@enum"]=enumerator,["@friendly"]=friendly,["@description"]=description,
                        ["@manufacturer"]=V(key,"Mfg"),["@hardware"]=V(key,"HardwareID"),
                        ["@compatible"]=V(key,"CompatibleIDs"),["@service"]=V(key,"Service"),["@class"]=guid,
                        ["@container"]=V(key,"ContainerID"),["@location"]=V(key,"LocationInformation"),
                        ["@last"]=key.LastWriteTime?.UtcDateTime.ToString("O"),["@key"]=path,["@source"]=source,
                        ["@raw"]=JsonSerializer.Serialize(raw),["@file"]=Path.GetFileName(source) })
                        cmd.Parameters.AddWithValue(parameter.Key,parameter.Value ?? DBNull.Value);
                    cmd.ExecuteNonQuery();
                    ArtifactProvenance.RecordKey(db, tx, "disk_devices_results", source, path, key.LastWriteTime);
                    inserted++;
                }
            }
        }
        tx.Commit(); progress?.Report($"Disk Devices: {inserted:N0} registry device instances"); return inserted;
    }
}
