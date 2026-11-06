using Registry;
using System.Data.SQLite;
using System.Security.Cryptography;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public static class NativeRegistryParsers
{
        private const string ParserVersion = "PrismNative.Registry.RunMRU/0.1";

        public static void CreateTables(SQLiteConnection connection)
        {
            using var command = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS native_runmru_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ArtifactType TEXT,
                ValueLetter TEXT,
                CommandTyped TEXT,
                RawValueText TEXT,
                MRUPosition INTEGER,
                MRUList TEXT,
                RegistryKey TEXT,
                HivePath TEXT,
                HiveSha256 TEXT,
                UserProfile TEXT,
                SourceParser TEXT,
                ParserVersion TEXT,
                Confidence INTEGER,
                ParserNotes TEXT,
                Potential_Activity TEXT,
                File TEXT,
                Label TEXT,
                Comment TEXT,
                FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
            command.ExecuteNonQuery();

            using var shellbagsCommand = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS native_shellbags_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ArtifactType TEXT,
                SourceHive TEXT,
                BagPath TEXT,
                ValueName TEXT,
                Slot INTEGER,
                MruOrder INTEGER,
                CleanPath TEXT,
                DisplayName TEXT,
                ShortName TEXT,
                LongName TEXT,
                ShellType TEXT,
                NamespaceGuid TEXT,
                MftEntry INTEGER,
                MftSequence INTEGER,
                RegistryKey TEXT,
                CreatedOn TEXT,
                ModifiedOn TEXT,
                AccessedOn TEXT,
                LastWrite TEXT,
                HivePath TEXT,
                HiveSha256 TEXT,
                UserProfile TEXT,
                SourceParser TEXT,
                ParserVersion TEXT,
                Confidence INTEGER,
                ParserNotes TEXT,
                RawBlobHex TEXT,
                Potential_Activity TEXT,
                File TEXT,
                Label TEXT,
                Comment TEXT,
                FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
            shellbagsCommand.ExecuteNonQuery();
            ArtifactSchema.EnsureColumns(connection, "native_shellbags_results", ("MftEntry", "INTEGER"), ("MftSequence", "INTEGER"), ("ParentSlot","INTEGER"));

        }

        public static int ParseRunMRU(string ntuserPath, string userProfile, string connectionString, IProgress<string>? progress = null)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                return 0;
            if (string.IsNullOrWhiteSpace(ntuserPath) || !File.Exists(ntuserPath))
                return 0;

            const string keyPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
            try
            {
                var hive = new RegistryHiveOnDemand(ntuserPath);
                var key = hive.GetKey(keyPath);
                if (key?.Values == null)
                    return 0;

                string mruList = key.Values.FirstOrDefault(v => v.ValueName.Equals("MRUList", StringComparison.OrdinalIgnoreCase))?.ValueData ?? "";
                string hiveSha256 = Sha256File(ntuserPath);

                using var conn = new SQLiteConnection(connectionString);
                conn.Open();
                using var tx = conn.BeginTransaction();

                int inserted = 0;
                foreach (var value in key.Values)
                {
                    string valueName = value.ValueName ?? "";
                    if (valueName.Equals("MRUList", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Equals("(default)", StringComparison.OrdinalIgnoreCase) ||
                        string.IsNullOrWhiteSpace(valueName))
                        continue;

                    string raw = value.ValueData ?? "";
                    string command = NormalizeRunMruCommand(raw);
                    if (string.IsNullOrWhiteSpace(command))
                        continue;

                    int mruPosition = GetMruPosition(mruList, valueName);
                    int confidence = valueName.Length == 1 && mruPosition >= 0 ? 95 : 75;
                    string notes = BuildRunMruNotes(raw, command, valueName, mruPosition);

                    using var insert = new SQLiteCommand(@"INSERT INTO native_runmru_results
                        (ArtifactType, ValueLetter, CommandTyped, RawValueText, MRUPosition, MRUList, RegistryKey,
                         HivePath, HiveSha256, UserProfile, SourceParser, ParserVersion, Confidence, ParserNotes,
                         Potential_Activity, File, Label, Comment)
                        VALUES ('RunMRU',@ValueLetter,@CommandTyped,@RawValueText,@MRUPosition,@MRUList,@RegistryKey,
                         @HivePath,@HiveSha256,@UserProfile,@SourceParser,@ParserVersion,@Confidence,@ParserNotes,
                         'Run Dialog Command',@File,'','')", conn, tx);
                    Add(insert, "@ValueLetter", valueName);
                    Add(insert, "@CommandTyped", command);
                    Add(insert, "@RawValueText", raw);
                    Add(insert, "@MRUPosition", mruPosition);
                    Add(insert, "@MRUList", mruList);
                    Add(insert, "@RegistryKey", keyPath);
                    Add(insert, "@HivePath", ntuserPath);
                    Add(insert, "@HiveSha256", hiveSha256);
                    Add(insert, "@UserProfile", userProfile ?? "");
                    Add(insert, "@SourceParser", "PrismNative");
                    Add(insert, "@ParserVersion", ParserVersion);
                    Add(insert, "@Confidence", confidence);
                    Add(insert, "@ParserNotes", notes);
                    Add(insert, "@File", Path.GetFileName(ntuserPath));
                    insert.ExecuteNonQuery();

                    ArtifactProvenance.RecordKey(conn, tx, "native_runmru_results", ntuserPath, keyPath, key.LastWriteTime);

                    inserted++;
                }

                tx.Commit();
                if (inserted > 0)
                    progress?.Report($"Native RunMRU ({userProfile}): {inserted} entries");
                return inserted;
            }
            catch (Exception ex)
            {
                progress?.Report($"Native RunMRU parse error: {ex}");
                return 0;
            }
        }

        public static int ParseShellbags(string hivePath, string connectionString, IProgress<string>? progress = null)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                return 0;
            if (string.IsNullOrWhiteSpace(hivePath) || !File.Exists(hivePath))
                return 0;

            string fileName = Path.GetFileName(hivePath);
            bool isUsrClass = fileName.Equals("UsrClass.dat", StringComparison.OrdinalIgnoreCase);
            string sourceHive = isUsrClass ? "UsrClass.dat" : "NTUSER.DAT";
            string bagMruRoot = isUsrClass
                ? @"Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
                : @"Software\Microsoft\Windows\Shell\BagMRU";
            string userProfile = InferUserProfileFromHivePath(hivePath);

            try
            {
                var hive = new RegistryHiveOnDemand(hivePath);
                var root = hive.GetKey(bagMruRoot);
                if (root == null)
                    return 0;

                string hiveSha256 = Sha256File(hivePath);
                using var conn = new SQLiteConnection(connectionString);
                conn.Open();
                using var tx = conn.BeginTransaction();

                int inserted = 0;
                var stack = new Stack<(string keyPath, string parentPath, int depth)>();
                var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                stack.Push((bagMruRoot, "", 0));
                while (stack.Count > 0)
                {
                    var (keyPath, parentPath, depth) = stack.Pop();
                    if (depth > 256 || !visited.Add(keyPath))
                        continue;

                    var key = hive.GetKey(keyPath);
                    if (key == null)
                        continue;

                    var mruOrder = BuildMruOrderMap(key);
                    int slot = GetNodeSlot(key);
                    string lastWrite = key.LastWriteTime.HasValue
                        ? key.LastWriteTime.Value.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
                        : "";

                    foreach (var value in key.Values)
                    {
                        if (!int.TryParse(value.ValueName, out int valueIndex))
                            continue;

                        byte[] blob = value.ValueDataRaw;
                        if (blob == null || blob.Length < 3)
                            continue;

                        var item = ParseShellItem(blob, parentPath.EndsWith(".zip",StringComparison.OrdinalIgnoreCase) ||
                            parentPath.Contains(".zip\\",StringComparison.OrdinalIgnoreCase));
                        if (string.IsNullOrWhiteSpace(item.DisplayName))
                            continue;

                        string cleanPath = CombineShellPath(parentPath, item.DisplayName);
                        int itemSlot=GetNodeSlot(hive.GetKey(keyPath+"\\"+value.ValueName));
                        int order = mruOrder.TryGetValue(valueIndex, out int mappedOrder) ? mappedOrder : -1;
                        var times = ExtractShellbagTimes(blob);
                        string notes = BuildShellbagNotes(item);
                        var mft = ExtractMftReference(blob);
                        string potentialActivity = item.Confidence < 60 ? "Unresolved Shell Item"
                            : item.NamespaceGuid != null ? "Shell Namespace Reference"
                            : item.ShellType.Contains("Volume", StringComparison.OrdinalIgnoreCase) ? "Drive Access" : "Folder Navigation";

                        using var insert = new SQLiteCommand(@"INSERT INTO native_shellbags_results
                            (ArtifactType, SourceHive, BagPath, ValueName, Slot, MruOrder, CleanPath, DisplayName,
                             ShortName, LongName, ShellType, CreatedOn, ModifiedOn, AccessedOn, LastWrite,
                             HivePath, HiveSha256, UserProfile, SourceParser, ParserVersion, Confidence, ParserNotes,
                             RawBlobHex, Potential_Activity, File, Label, Comment, NamespaceGuid, RegistryKey, MftEntry, MftSequence, ParentSlot)
                            VALUES ('Shellbags',@SourceHive,@BagPath,@ValueName,@Slot,@MruOrder,@CleanPath,@DisplayName,
                             @ShortName,@LongName,@ShellType,@CreatedOn,@ModifiedOn,@AccessedOn,@LastWrite,
                             @HivePath,@HiveSha256,@UserProfile,'PrismNative','PrismNative.Registry.Shellbags/0.4',
                             @Confidence,@ParserNotes,@RawBlobHex,@PotentialActivity,@File,'','',@NamespaceGuid,@RegistryKey,@MftEntry,@MftSequence,@ParentSlot)", conn, tx);
                        Add(insert, "@SourceHive", sourceHive);
                        Add(insert, "@BagPath", keyPath + "\\" + value.ValueName);
                        Add(insert, "@ValueName", value.ValueName);
                        Add(insert, "@Slot", itemSlot >= 0 ? itemSlot : DBNull.Value);
                        Add(insert, "@ParentSlot", slot >= 0 ? slot : DBNull.Value);
                        Add(insert, "@MruOrder", order >= 0 ? order : DBNull.Value);
                        Add(insert, "@CleanPath", cleanPath);
                        Add(insert, "@DisplayName", item.DisplayName);
                        Add(insert, "@ShortName", item.ShortName);
                        Add(insert, "@LongName", item.LongName);
                        Add(insert, "@ShellType", item.ShellType);
                        Add(insert, "@NamespaceGuid", item.NamespaceGuid);
                        Add(insert, "@MftEntry", mft.entry.HasValue ? mft.entry.Value : DBNull.Value);
                        Add(insert, "@MftSequence", mft.sequence.HasValue ? mft.sequence.Value : DBNull.Value);
                        Add(insert, "@RegistryKey", keyPath);
                        Add(insert, "@CreatedOn", times.created);
                        Add(insert, "@ModifiedOn", times.modified);
                        Add(insert, "@AccessedOn", times.accessed);
                        Add(insert, "@LastWrite", lastWrite);
                        Add(insert, "@HivePath", hivePath);
                        Add(insert, "@HiveSha256", hiveSha256);
                        Add(insert, "@UserProfile", userProfile);
                        Add(insert, "@Confidence", item.Confidence);
                        Add(insert, "@ParserNotes", notes);
                        Add(insert, "@RawBlobHex", Convert.ToHexString(blob));
                        Add(insert, "@PotentialActivity", potentialActivity);
                        Add(insert, "@File", Path.GetFileName(hivePath));
                        insert.ExecuteNonQuery();

                        inserted++;

                        stack.Push((keyPath + "\\" + value.ValueName, cleanPath, depth + 1));
                    }
                }

                tx.Commit();
                if (inserted > 0)
                    progress?.Report($"Native ShellBags ({userProfile}): {inserted} entries");
                return inserted;
            }
            catch (Exception ex)
            {
                progress?.Report($"Native ShellBags parse error: {ex}");
                return 0;
            }
        }

        private static string NormalizeRunMruCommand(string raw)
        {
            if (string.IsNullOrEmpty(raw))
                return "";

            string command = raw;
            int controlTerminator = command.IndexOf('\u0001');
            if (controlTerminator >= 0)
                command = command[..controlTerminator];

            if (command.EndsWith(@"\1", StringComparison.Ordinal))
                command = command[..^2];

            return command.Trim('\0', ' ', '\t', '\r', '\n');
        }

        private static int GetMruPosition(string mruList, string valueName)
        {
            if (string.IsNullOrEmpty(mruList) || string.IsNullOrEmpty(valueName) || valueName.Length != 1)
                return -1;

            int position = mruList.IndexOf(valueName[0]);
            return position >= 0 ? position : -1;
        }

        private static string BuildRunMruNotes(string raw, string command, string valueName, int mruPosition)
        {
            var notes = new List<string>();
            if (!string.Equals(raw, command, StringComparison.Ordinal))
                notes.Add("Removed RunMRU command terminator.");
            if (valueName.Length != 1)
                notes.Add("Unexpected RunMRU value name length.");
            if (mruPosition < 0)
                notes.Add("Value was not present in MRUList order.");
            return notes.Count == 0 ? "Parsed from NTUSER RunMRU value." : string.Join(" ", notes);
        }

        private sealed record ShellItemResult(string DisplayName, string? ShortName, string? LongName, string ShellType, int Confidence, List<string> Notes, string? NamespaceGuid);

        private static ShellItemResult ParseShellItem(byte[] blob, bool zipAncestor = false)
        {
            int itemSize = blob.Length >= 2 ? BitConverter.ToUInt16(blob, 0) : 0;
            if (itemSize < 3 || itemSize > blob.Length)
                return new ShellItemResult("(invalid shell item)", null, null, "Invalid", 0,
                    new List<string> { "Invalid shell item size; raw bytes retained." }, null);
            if (itemSize < blob.Length) blob = blob[..itemSize];
            byte type = blob.Length > 2 ? blob[2] : (byte)0;
            string shellType = ShellItemType(type);
            string? shortName = ExtractShortName(blob);
            string? longName = ExtractStructuredLongName(blob);
            var notes = new List<string>();
            string? namespaceGuid = null;

            string? display = null;
            int confidence = 70;

            if (type == 0x1F && blob.Length >= 20)
            {
                try
                {
                    if (blob[3] == 0 && blob.Length > 20)
                    {
                        display = new Lnk.ShellItems.ShellBag0X1F(blob, 1252).Value;
                        notes.Add("Structured extended root shell item; not a fixed-offset GUID.");
                    }
                    else
                    {
                    var guid = new Guid(blob[4..20]);
                    namespaceGuid = guid.ToString("B");
                    display = KnownShellGuids.TryGetValue(guid, out string? known) ? known : guid.ToString("B");
                    confidence = KnownShellGuids.ContainsKey(guid) ? 95 : 60;
                    if (!KnownShellGuids.ContainsKey(guid))
                        notes.Add("Unknown shell GUID.");
                    }
                }
                catch { }
            }
            else if ((type & 0x70) == 0x20)
            {
                if ((type & 0x01) == 0 && blob.Length >= 20)
                {
                    var guid = new Guid(blob[4..20]);
                    namespaceGuid = guid.ToString("B");
                    display = KnownShellGuids.TryGetValue(guid, out string? known) ? known : namespaceGuid;
                    shellType = "Namespace / GUID";
                    confidence = known != null ? 95 : 60;
                    notes.Add(known != null ? "Known namespace GUID; no ASCII volume name is present." : "Namespace GUID decoded; friendly name unresolved. No ASCII volume name is present.");
                }
                else
                {
                    display = ExtractAsciiString(blob, 3, 20);
                    confidence = LooksLikeDrive(display) ? 95 : 60;
                }
            }
            else if (zipAncestor && type == 0x3A && TryReadCompressedName(blob,out string archiveName))
            {
                display = longName = archiveName;
                shellType = "Compressed archive entry (Windows 10)";
                confidence = 95;
                notes.Add("ZIP ancestor and bounded Windows 10 compressed-folder UTF-16 name fields.");
            }
            else if ((type & 0x70) == 0x30)
            {
                display = !string.IsNullOrWhiteSpace(longName) ? longName : shortName;
                confidence = !string.IsNullOrWhiteSpace(longName) ? 95 : 70;
                if (string.IsNullOrWhiteSpace(longName) && LooksLikeDosName(shortName))
                    notes.Add("Only 8.3 short name was available.");
            }
            else if (TryReadWebFolderItem(blob, out string webName, out _))
            {
                display = webName;
                confidence = 95;
                notes.Add("Bounded C001B000 web-folder properties; name and URL retained in raw bytes.");
            }
            else
            {
                try
                {
                    Lnk.ShellItems.IShellBag? decoded = type switch
                    {
                        0x00 => new Lnk.ShellItems.ShellBag0X00(blob, 1252),
                        0x01 => new Lnk.ShellItems.ShellBag0X01(blob),
                        0x40 or 0x41 or 0x42 or 0x46 or 0x47 => new Lnk.ShellItems.ShellBag0X40(blob, 1252),
                        0x61 => new Lnk.ShellItems.ShellBag0X61(blob, 1252),
                        0x71 => new Lnk.ShellItems.ShellBag0X71(blob),
                        0x74 => new Lnk.ShellItems.ShellBag0X74(blob, 1252),
                        0xC3 => new Lnk.ShellItems.ShellBag0Xc3(blob, 1252),
                        _ => null
                    };
                    display = decoded?.Value;
                    confidence = IsReadableShellName(display) ? 80 : 35;
                    notes.Add("Structured LNK shell-item decoder; raw bytes retained.");
                }
                catch (Exception ex)
                {
                    confidence = 0;
                    notes.Add($"Shell item decoder rejected data: {ex.GetType().Name}.");
                }

                if (confidence < 70)
                    notes.Add($"Best-effort parse for shell item type 0x{type:X2}.");
            }

            display = CleanShellName(display);
            if (string.IsNullOrWhiteSpace(display) || !IsReadableShellName(display))
            {
                display = $"(type 0x{type:X2})";
                confidence = Math.Min(confidence, 35);
                notes.Add("No reliable display name decoded.");
            }

            return new ShellItemResult(display, shortName, longName, shellType, confidence, notes, namespaceGuid);
        }

        private static string ShellItemType(byte type)
        {
            return (type & 0x70) switch
            {
                0x10 => "Root / GUID",
                0x20 => "Volume",
                0x30 => "File Entry",
                0x40 => "Network Location",
                0x60 => "URI",
                0x70 => "Control Panel / Known Folder",
                _ => $"Unknown (0x{type:X2})"
            };
        }

        private static Dictionary<int, int> BuildMruOrderMap(dynamic key)
        {
            var result = new Dictionary<int, int>();
            byte[]? data = null;
            foreach (var value in key.Values)
            {
                if (string.Equals((string?)value.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
                {
                    data = value.ValueDataRaw;
                    break;
                }
            }
            if (data == null)
                return result;

            int order = 0;
            for (int i = 0; i + 3 < data.Length; i += 4)
            {
                int idx = BitConverter.ToInt32(data, i);
                if (idx == -1)
                    break;
                result[idx] = order++;
            }

            return result;
        }

        private static int GetNodeSlot(dynamic key)
        {
            if (key?.Values == null) return -1;
            foreach (var value in key.Values)
            {
                if (!string.Equals((string?)value.ValueName, "NodeSlot", StringComparison.OrdinalIgnoreCase))
                    continue;

                byte[]? data = value.ValueDataRaw;
                return data != null && data.Length >= 4 ? BitConverter.ToInt32(data, 0) : -1;
            }

            return -1;
        }

        public static string ParsePidlPath(byte[]? data, int offset = 0, bool absoluteDesktopRoot = false)
        {
            if (data == null || offset < 0 || offset > data.Length) return "";
            var parts = new List<string>();
            string? webUrl = null;
            bool webNamespace = offset >= 0 && offset + 20 <= data.Length && data[offset + 2] == 0x1F &&
                new Guid(data[(offset + 4)..(offset + 20)]) == new Guid("b28aa736-876b-46da-b3a8-84c5e30ba492");


            if (absoluteDesktopRoot && offset >= 0 && offset + 3 <= data.Length &&
                (data[offset + 2] & 0x70) == 0x30)
                parts.Add("Desktop");
            while (offset + 2 <= data.Length)
            {
                int size = BitConverter.ToUInt16(data, offset);
                if (size == 0) break;
                if (size < 3 || offset + size > data.Length) return "";
                var bytes = data[offset..(offset + size)];
                var item = ParseShellItem(bytes,parts.Any(p=>p.EndsWith(".zip",StringComparison.OrdinalIgnoreCase)));
                if (webNamespace && TryReadWebFolderItem(bytes, out _, out string url))
                    webUrl = url;
                else if (parts.Count > 0)
                    webNamespace = false;
                parts.Add(item.DisplayName.TrimEnd('\\'));
                offset += size;
            }
            return webNamespace && webUrl != null ? webUrl : string.Join("\\", parts);
        }

        private static bool TryReadWebFolderItem(byte[] blob, out string name, out string url)
        {
            name = url = "";
            if (blob.Length < 16 || blob[2] != 0 || BitConverter.ToUInt32(blob,4) != 0xC001B000) return false;
            uint end = BitConverter.ToUInt32(blob,8), count = BitConverter.ToUInt32(blob,12);
            if (end < 16 || end > blob.Length || count > (end - 16) / 8) return false;
            int position = 16;
            var utf16 = new UnicodeEncoding(false,false,true);
            try
            {
                for (int i=0;i<count;i++)
                {
                    if (position > end - 8) return false;
                    uint property = BitConverter.ToUInt32(blob,position), length = BitConverter.ToUInt32(blob,position+4);
                    position += 8;
                    if (length > end - position) return false;
                    if (property is 7 or 14)
                    {
                        if (length < 2 || length % 2 != 0 || blob[position+(int)length-1]!=0 || blob[position+(int)length-2]!=0) return false;
                        string value=utf16.GetString(blob,position,(int)length-2);
                        if (property == 7) name=value; else url=value;
                    }
                    position += (int)length;
                }
                return position == end && !string.IsNullOrWhiteSpace(name) &&
                    Uri.TryCreate(url,UriKind.Absolute,out Uri? uri) && uri.Scheme is "http" or "https";
            }
            catch (DecoderFallbackException) { return false; }
        }

        private static bool TryReadCompressedName(byte[] blob,out string name)
        {
            name="";
            if (blob.Length<100 || BitConverter.ToUInt16(blob,24) is not (0 or 8)) return false;
            uint count=BitConverter.ToUInt32(blob,84),second=BitConverter.ToUInt32(blob,88);
            long end=92L+2L*count+2+2L*second+2+4;
            if (count==0 || end!=blob.Length) return false;
            int terminator=92+(int)count*2;
            if (blob[terminator]!=0 || blob[terminator+1]!=0) return false;
            int secondTerminator=terminator+2+(int)second*2;
            if (blob[secondTerminator]!=0 || blob[secondTerminator+1]!=0) return false;
            try
            {
                name=new UnicodeEncoding(false,false,true).GetString(blob,92,(int)count*2);
                return !string.IsNullOrWhiteSpace(name) && !name.Contains('\0');
            }
            catch (DecoderFallbackException) { return false; }
        }

        private static string? ExtractShortName(byte[] blob)
        {
            if (blob.Length <= 0x0E || (blob[2] & 0x70) != 0x30)
                return null;
            if ((blob[2] & 0x04) == 0) return CleanShellName(ExtractAsciiString(blob, 0x0E));
            int end = 0x0E;
            while (end + 1 < blob.Length && (blob[end] != 0 || blob[end + 1] != 0)) end += 2;
            if (end + 1 >= blob.Length) return null;
            try { return CleanShellName(new UnicodeEncoding(false, false, true).GetString(blob, 0x0E, end - 0x0E)); }
            catch (DecoderFallbackException) { return null; }
        }

        private static string? ExtractBestUnicodeName(byte[] blob, string? shortName)
        {
            var candidates = ExtractUnicodeStrings(blob)
                .Select(CleanShellName)
                .Where(IsReadableShellName)
                .OfType<string>()
                .Where(s => !s.StartsWith("@", StringComparison.Ordinal))
                .Where(s => !s.Contains(".dll,", StringComparison.OrdinalIgnoreCase))
                .Where(s => !string.Equals(s, shortName, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(s => ScoreShellName(s, shortName))
                .ToList();
            return candidates.FirstOrDefault();
        }

        private static IEnumerable<(int offset, int size, int version)> ShellExtensions(byte[] blob)
        {
            if (blob.Length < 4) yield break;
            int itemSize = BitConverter.ToUInt16(blob, 0);
            if (itemSize < 4 || itemSize > blob.Length) yield break;
            int offset = BitConverter.ToUInt16(blob, itemSize - 2);
            if (offset < 4) yield break;
            while (offset + 8 <= itemSize - 2)
            {
                int size = BitConverter.ToUInt16(blob, offset);
                if (size < 8 || offset + size > itemSize) yield break;
                if (BitConverter.ToUInt32(blob, offset + 4) == 0xBEEF0004)
                    yield return (offset, size, BitConverter.ToUInt16(blob, offset + 2));
                offset += size;
            }
        }

        private static string? ExtractStructuredLongName(byte[] blob)
        {
            foreach (var extension in ShellExtensions(blob))
            {
                if (extension.version < 3) continue;
                int start = extension.offset + 18;
                if (extension.version >= 7) start += 18;
                start += 2;
                if (extension.version >= 9) start += 4;
                if (extension.version >= 8) start += 4;
                int end = start;
                int limit = extension.offset + extension.size;
                while (end + 1 < limit && BitConverter.ToUInt16(blob, end) != 0) end += 2;
                if (end > start && end + 1 < limit)
                    return Encoding.Unicode.GetString(blob, start, end - start);
            }
            return null;
        }

        private static (long? entry, int? sequence) ExtractMftReference(byte[] blob)
        {
            foreach (var extension in ShellExtensions(blob))
            {
                if (extension.version < 7 || extension.size < 28) continue;
                ulong reference = BitConverter.ToUInt64(blob, extension.offset + 20);
                if (reference == 0) return (null, null);
                return ((long)(reference & 0x0000FFFFFFFFFFFFUL), (int)(reference >> 48));
            }
            return (null, null);
        }

        private static IEnumerable<string> ExtractUnicodeStrings(byte[] data)
        {
            int start = -1;
            for (int i = 0; i + 1 < data.Length; i += 2)
            {
                bool printable = data[i] >= 0x20 && data[i] <= 0x7E && data[i + 1] == 0;
                if (printable)
                {
                    if (start < 0) start = i;
                }
                else if (start >= 0)
                {
                    int length = i - start;
                    if (length >= 6)
                        yield return Encoding.Unicode.GetString(data, start, length);
                    start = -1;
                }
            }
            if (start >= 0 && data.Length - start >= 6)
                yield return Encoding.Unicode.GetString(data, start, data.Length - start - ((data.Length - start) % 2));
        }

        private static string? ExtractBestAsciiName(byte[] data)
        {
            var matches = ExtractAsciiStrings(data, 3).ToList();

            return matches.Select(CleanShellName).Where(IsReadableShellName).OfType<string>().OrderByDescending(s => ScoreShellName(s, null)).FirstOrDefault();
        }

        private static string? ExtractUncPath(byte[] data)
        {
            foreach (string candidate in ExtractAsciiStrings(data, 5).Select(s => s.Trim('\0', ' ', '\t', '\r', '\n')))
            {
                int uncStart = candidate.IndexOf(@"\\", StringComparison.Ordinal);
                if (uncStart < 0)
                    continue;

                string unc = candidate[uncStart..];
                int end = unc.IndexOfAny(['"', '\'', '<', '>', '|']);
                if (end > 0)
                    unc = unc[..end];

                unc = unc.TrimEnd('\0', ' ', '\t', '\r', '\n');
                if (unc.Count(c => c == '\\') >= 3)
                    return unc;
            }

            return null;
        }

        private static IEnumerable<string> ExtractAsciiStrings(byte[] data, int minimumLength)
        {
            int start = -1;
            for (int i = 0; i < data.Length; i++)
            {
                bool printable = data[i] >= 0x20 && data[i] <= 0x7E;
                if (printable)
                {
                    if (start < 0) start = i;
                }
                else if (start >= 0)
                {
                    if (i - start >= minimumLength)
                        yield return Encoding.ASCII.GetString(data, start, i - start);
                    start = -1;
                }
            }
            if (start >= 0 && data.Length - start >= minimumLength)
                yield return Encoding.ASCII.GetString(data, start, data.Length - start);
        }

        private static string? ExtractAsciiString(byte[] data, int start, int? maxLength = null)
        {
            if (start < 0 || start >= data.Length)
                return null;
            int limit = Math.Min(data.Length, start + (maxLength ?? data.Length - start));
            int end = Array.IndexOf(data, (byte)0, start, limit - start);
            if (end < 0) return null;
            for (int i = start; i < end; i++)
                if (data[i] < 0x20 || data[i] > 0x7E) return null;
            return end > start ? Encoding.ASCII.GetString(data, start, end - start) : null;
        }

        private static string? CleanShellName(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;
            var builder = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                if (char.IsControl(c))
                    continue;
                builder.Append(c);
            }
            return builder.ToString().Trim('\0', ' ', '\t', '\r', '\n');
        }

        private static bool IsReadableShellName(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;
            int printable = value.Count(c => !char.IsControl(c));
            return printable >= Math.Min(3, value.Length) && !value.Contains('\uFFFD');
        }

        private static int ScoreShellName(string value, string? shortName)
        {
            int score = value.Length;
            if (value.Contains(' ')) score += 10;
            if (!LooksLikeDosName(value)) score += 15;
            if (!string.IsNullOrWhiteSpace(shortName) && value.StartsWith(shortName.Replace("~1", "", StringComparison.OrdinalIgnoreCase), StringComparison.OrdinalIgnoreCase))
                score += 5;
            if (value.StartsWith("@", StringComparison.Ordinal)) score -= 30;
            if (value.Contains(".dll,", StringComparison.OrdinalIgnoreCase)) score -= 30;
            return score;
        }

        private static bool LooksLikeDosName(string? value)
        {
            return !string.IsNullOrWhiteSpace(value) && value.Contains('~') && value.Length <= 12;
        }

        private static bool LooksLikeDrive(string? value)
        {
            return !string.IsNullOrWhiteSpace(value) && value.Length >= 2 && value[1] == ':';
        }

        private static string CombineShellPath(string parent, string child)
        {
            if (child.StartsWith(@"\\", StringComparison.Ordinal))
                return child;
            if (string.IsNullOrWhiteSpace(parent))
                return child;
            if (parent.EndsWith("\\", StringComparison.Ordinal))
                return parent + child;
            return parent + "\\" + child;
        }

        private static string BuildShellbagNotes(ShellItemResult item)
        {
            return item.Notes.Count == 0 ? "Native ShellBag shell item parse." : string.Join(" ", item.Notes);
        }

        private static (string? created, string? modified, string? accessed) ExtractShellbagTimes(byte[] blob)
        {

            if (blob.Length >= 3 && blob[2] == 0x3A) return (null,null,null);
            string? modified = null;
            int fileEntryOffset = 0;
            if (blob.Length >= 24 && blob[2] == 0x74 && blob.AsSpan(6, 4).SequenceEqual("CFSF"u8))
            {
                int embeddedSize = BitConverter.ToUInt16(blob, 10);
                if (embeddedSize >= 14 && 10 + embeddedSize <= blob.Length && (blob[12] & 0x70) == 0x30)
                    fileEntryOffset = 10;
            }
            if (blob.Length >= fileEntryOffset + 0x0C && (blob[fileEntryOffset + 2] & 0x70) == 0x30)
            {
                ushort fatDate = BitConverter.ToUInt16(blob, fileEntryOffset + 0x08);
                ushort fatTime = BitConverter.ToUInt16(blob, fileEntryOffset + 0x0A);
                modified = DecodeFatTimestamp(fatDate, fatTime);
            }

            string? created = null;
            string? accessed = null;
            foreach (var extension in ShellExtensions(blob))
            {
                int i = extension.offset + 4;
                if (extension.size >= 18)
                {
                    try
                    {

                        created = DecodeFatTimestamp(BitConverter.ToUInt16(blob, i + 4), BitConverter.ToUInt16(blob, i + 6));
                    }
                    catch { }
                    try
                    {
                        accessed = DecodeFatTimestamp(BitConverter.ToUInt16(blob, i + 8), BitConverter.ToUInt16(blob, i + 10));
                    }
                    catch { }
                    break;
                }
            }

            return (created, modified, accessed);
        }

        private static string? DecodeFatTimestamp(ushort date, ushort time)
        {
            if (date == 0)
                return null;
            try
            {
                int year = ((date >> 9) & 0x7F) + 1980;
                int month = (date >> 5) & 0x0F;
                int day = date & 0x1F;
                int hour = (time >> 11) & 0x1F;
                int minute = (time >> 5) & 0x3F;
                int second = (time & 0x1F) * 2;
                if (month < 1 || month > 12 || day < 1 || day > 31)
                    return null;
                return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc).ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }
            catch { return null; }
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

        private static readonly Dictionary<Guid, string> KnownShellGuids = new()
        {
            { new Guid("{20D04FE0-3AEA-1069-A2D8-08002B30309D}"), "This PC" },
            { new Guid("{450D8FBA-AD25-11D0-98A8-0800361B1103}"), "Documents" },
            { new Guid("{645FF040-5081-101B-9F08-00AA002F954E}"), "Recycle Bin" },
            { new Guid("{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"), "Network" },
            { new Guid("{59031A47-3F72-44A7-89C5-5595FE6B30EE}"), "Users" },
            { new Guid("{031E4825-7B94-4DC3-B131-E946B44C8DD5}"), "Libraries" },
            { new Guid("{018D5C66-4533-4307-9B53-224DE2ED1FE6}"), "OneDrive" },
            { new Guid("{679F85CB-0220-4080-B29B-5540CC05AAB6}"), "Quick Access" },
            { new Guid("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"), "Desktop" }
        };

        private static string Sha256File(string path)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }

        private static void Add(SQLiteCommand command, string name, object? value)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
}
