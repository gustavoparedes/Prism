using Registry;
using System.Data.SQLite;
using System.Globalization;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record UserAccountsParseResult(int Inserted);

public static class SamRegistryParsers
{
    public static void CreateTables(SQLiteConnection connection)
    {
        using var userAccounts = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS user_accounts_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            RID INTEGER,
            Username TEXT,
            FullName TEXT,
            Description TEXT,
            LastLogon TEXT,
            LastPasswordChange TEXT,
            LastIncorrectPassword TEXT,
            AccountExpires TEXT,
            LogonCount INTEGER,
            FailedPasswordCount INTEGER,
            AccountDisabled INTEGER,
            PasswordNotRequired INTEGER,
            PasswordNeverExpires INTEGER,
            AccountAutoLocked INTEGER,
            AccountType TEXT,
            GroupMemberships TEXT,
            HomeDirectory TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        userAccounts.ExecuteNonQuery();
    }

    public static UserAccountsParseResult ParseUserAccounts(
        string samHivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(samHivePath) ||
            !File.Exists(samHivePath))
        {
            return new UserAccountsParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(samHivePath);
            var usersKey = hive.GetKey(@"SAM\Domains\Account\Users");
            if (usersKey?.SubKeys == null)
                return new UserAccountsParseResult(0);

            var userGroupMap = BuildUserGroupMap(hive);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var userStub in usersKey.SubKeys)
            {
                string ridHex = userStub.KeyName ?? "";
                if (ridHex.Equals("Names", StringComparison.OrdinalIgnoreCase) ||
                    ridHex.Length != 8 ||
                    !uint.TryParse(ridHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint rid) ||
                    rid == 0)
                {
                    continue;
                }

                var userKey = hive.GetKey($@"SAM\Domains\Account\Users\{ridHex}");
                if (userKey?.Values == null)
                    continue;

                var account = ReadAccountRecord(userKey, rid);
                string groups = userGroupMap.TryGetValue(rid, out var memberships) && memberships.Count > 0
                    ? string.Join(",", memberships)
                    : "";

                using var command = new SQLiteCommand(@"INSERT INTO user_accounts_results
                    (ArtifactType, RID, Username, FullName, Description, LastLogon,
                     LastPasswordChange, LastIncorrectPassword, AccountExpires, LogonCount,
                     FailedPasswordCount, AccountDisabled, PasswordNotRequired, PasswordNeverExpires,
                     AccountAutoLocked, AccountType, GroupMemberships, HomeDirectory,
                     Potential_Activity, File, Label, Comment)
                    VALUES ('User Account', @RID, @Username, @FullName, @Description, @LastLogon,
                     @LastPasswordChange, @LastIncorrectPassword, @AccountExpires, @LogonCount,
                     @FailedPasswordCount, @AccountDisabled, @PasswordNotRequired,
                     @PasswordNeverExpires, @AccountAutoLocked, @AccountType, @GroupMemberships,
                     @HomeDirectory, 'Local User Account', @File, '', '')",
                    connection,
                    transaction);
                command.Parameters.AddWithValue("@RID", (int)rid);
                command.Parameters.AddWithValue("@Username", account.Username);
                command.Parameters.AddWithValue("@FullName", account.FullName);
                command.Parameters.AddWithValue("@Description", account.Description);
                command.Parameters.AddWithValue("@LastLogon", account.LastLogon);
                command.Parameters.AddWithValue("@LastPasswordChange", account.LastPasswordChange);
                command.Parameters.AddWithValue("@LastIncorrectPassword", account.LastIncorrectPassword);
                command.Parameters.AddWithValue("@AccountExpires", account.AccountExpires);
                command.Parameters.AddWithValue("@LogonCount", account.LogonCount);
                command.Parameters.AddWithValue("@FailedPasswordCount", account.FailedPasswordCount);
                command.Parameters.AddWithValue("@AccountDisabled", account.AccountDisabled);
                command.Parameters.AddWithValue("@PasswordNotRequired", account.PasswordNotRequired);
                command.Parameters.AddWithValue("@PasswordNeverExpires", account.PasswordNeverExpires);
                command.Parameters.AddWithValue("@AccountAutoLocked", account.AccountAutoLocked);
                command.Parameters.AddWithValue("@AccountType", ClassifyAccount(rid, account.Username));
                command.Parameters.AddWithValue("@GroupMemberships", groups);
                command.Parameters.AddWithValue("@HomeDirectory", account.HomeDirectory);
                command.Parameters.AddWithValue("@File", Path.GetFileName(samHivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "user_accounts_results", samHivePath,
                    $@"SAM\Domains\Account\Users\{ridHex}", userKey.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"User Accounts: {inserted:N0} entries");

            return new UserAccountsParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"User Accounts parse error from {samHivePath}: {ex}");
            return new UserAccountsParseResult(0);
        }
    }

    private static Dictionary<uint, List<string>> BuildUserGroupMap(RegistryHiveOnDemand hive)
    {
        var aliasNames = new Dictionary<uint, string>
        {
            { 0x220, "Administrators" },
            { 0x221, "Users" },
            { 0x222, "Guests" },
            { 0x223, "Power Users" },
            { 0x227, "Backup Operators" },
            { 0x22B, "Remote Desktop Users" }
        };

        var userGroupMap = new Dictionary<uint, List<string>>();
        foreach (var alias in aliasNames)
        {
            var aliasKey = hive.GetKey($@"SAM\Domains\Builtin\Aliases\{alias.Key:X8}");
            byte[]? data = RawValue(aliasKey, "C");
            if (data == null || data.Length < 0x34)
                continue;

            for (int i = 0; i <= data.Length - 8; i++)
            {
                if (data[i] != 0x01 ||
                    data[i + 2] != 0x00 ||
                    data[i + 3] != 0x00 ||
                    data[i + 4] != 0x00 ||
                    data[i + 5] != 0x00 ||
                    data[i + 6] != 0x00 ||
                    data[i + 7] != 0x05)
                {
                    continue;
                }

                int subAuthorityCount = data[i + 1];
                int sidLength = 8 + subAuthorityCount * 4;
                if (subAuthorityCount <= 0 || subAuthorityCount > 15 || i + sidLength > data.Length)
                    continue;

                uint rid = BitConverter.ToUInt32(data, i + sidLength - 4);
                if (!userGroupMap.TryGetValue(rid, out var groups))
                {
                    groups = new List<string>();
                    userGroupMap[rid] = groups;
                }

                if (!groups.Contains(alias.Value))
                    groups.Add(alias.Value);

                i += sidLength - 1;
            }
        }

        return userGroupMap;
    }

    private static SamAccountRecord ReadAccountRecord(dynamic userKey, uint rid)
    {
        string username = $"RID_{rid}";
        string fullName = "";
        string description = "";
        string homeDirectory = "";
        string lastLogon = "";
        string lastPasswordChange = "";
        string lastIncorrectPassword = "";
        string accountExpires = "";
        int logonCount = 0;
        int failedPasswordCount = 0;
        int accountDisabled = 0;
        int passwordNotRequired = 0;
        int passwordNeverExpires = 0;
        int accountAutoLocked = 0;

        byte[]? f = RawValue(userKey, "F");
        if (f is { Length: >= 0x48 })
        {
            lastLogon = FileTimeToString(ReadInt64(f, 0x08));
            lastPasswordChange = FileTimeToString(ReadInt64(f, 0x18));
            long expires = ReadInt64(f, 0x20);
            accountExpires = expires == 0x7FFFFFFFFFFFFFFF ? "Never" : FileTimeToString(expires);
            lastIncorrectPassword = FileTimeToString(ReadInt64(f, 0x28));

            ushort flags = ReadUInt16(f, 0x38);
            accountDisabled = (flags & 0x0001) != 0 ? 1 : 0;
            passwordNotRequired = (flags & 0x0004) != 0 ? 1 : 0;
            passwordNeverExpires = (flags & 0x0200) != 0 ? 1 : 0;
            accountAutoLocked = (flags & 0x0400) != 0 ? 1 : 0;
            failedPasswordCount = ReadUInt16(f, 0x40);
            logonCount = ReadUInt16(f, 0x42);
        }

        byte[]? v = RawValue(userKey, "V");
        if (v is { Length: >= 0xCC })
        {
            string parsedUsername = ReadVString(v, 0x0C);
            if (!string.IsNullOrWhiteSpace(parsedUsername))
                username = parsedUsername;

            fullName = ReadVString(v, 0x18);
            description = ReadVString(v, 0x24);
            homeDirectory = ReadVString(v, 0x48);
        }

        return new SamAccountRecord(
            username,
            fullName,
            description,
            lastLogon,
            lastPasswordChange,
            lastIncorrectPassword,
            accountExpires,
            logonCount,
            failedPasswordCount,
            accountDisabled,
            passwordNotRequired,
            passwordNeverExpires,
            accountAutoLocked,
            homeDirectory);
    }

    private static string ReadVString(byte[] data, int headerOffset)
    {
        const int dataBase = 0xCC;
        try
        {
            int offset = BitConverter.ToInt32(data, headerOffset);
            int length = BitConverter.ToInt32(data, headerOffset + 4);
            if (length <= 0 || length > 4096 || dataBase + offset < 0 || dataBase + offset + length > data.Length)
                return "";

            return Encoding.Unicode.GetString(data, dataBase + offset, length).TrimEnd('\0');
        }
        catch
        {
            return "";
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

    private static string FileTimeToString(long fileTime)
    {
        try
        {
            return fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime).ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
        }
        catch
        {
            return "";
        }
    }

    private static long ReadInt64(byte[] data, int offset)
    {
        return offset >= 0 && offset + 8 <= data.Length ? BitConverter.ToInt64(data, offset) : 0;
    }

    private static ushort ReadUInt16(byte[] data, int offset)
    {
        return offset >= 0 && offset + 2 <= data.Length ? BitConverter.ToUInt16(data, offset) : (ushort)0;
    }

    private static string ClassifyAccount(uint rid, string username)
    {
        if (rid == 500) return "Administrator";
        if (rid == 501) return "Guest";
        if (rid == 503) return "DefaultAccount";
        if (rid == 504) return "WDAGUtilityAccount";
        if (username.Equals("HomeGroupUser$", StringComparison.OrdinalIgnoreCase)) return "HomeGroupUser";
        return rid >= 1000 ? "Regular User" : "System";
    }

    private sealed record SamAccountRecord(
        string Username,
        string FullName,
        string Description,
        string LastLogon,
        string LastPasswordChange,
        string LastIncorrectPassword,
        string AccountExpires,
        int LogonCount,
        int FailedPasswordCount,
        int AccountDisabled,
        int PasswordNotRequired,
        int PasswordNeverExpires,
        int AccountAutoLocked,
        string HomeDirectory);
}
