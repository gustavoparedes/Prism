using System.Globalization;
using System.Text.RegularExpressions;

namespace Prism.Core.Artifacts;

public sealed record TemporalDisplay(TimeZoneInfo Zone)
{
    public static implicit operator TemporalDisplay(TimeSpan offset) => new(TimeZoneInfo.CreateCustomTimeZone(
        "Fixed " + offset, offset, "Fixed " + offset, "Fixed " + offset));

    public string FormatUtc(string raw)
    {
        if (!TemporalContract.TryUtc(raw, out var utc)) return raw;
        int digits = Regex.Match(raw, @"\.(\d{1,7})").Groups[1].Length;
        string format = "yyyy-MM-dd HH:mm:ss" + (digits > 0 ? "." + new string('f', digits) : "") + " zzz";
        return TimeZoneInfo.ConvertTime(utc, Zone).ToString(format, CultureInfo.InvariantCulture);
    }

    public DateTimeOffset? ParseBoundary(string? text, bool endOfDate = false)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        text = text.Trim();
        if (!Regex.IsMatch(text, @"^\d{4}-\d{2}-\d{2}(?:$|[T ])"))
            throw new FormatException("Invalid or ambiguous date format; an ISO date is required.");
        if (TemporalContract.HasOffset(text))
        {
            if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var explicitTime))
                throw new FormatException("Invalid timestamp with offset.");
            return explicitTime.ToUniversalTime();
        }
        if (!DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var wall))
            throw new FormatException("Invalid date/time.");
        wall = DateTime.SpecifyKind(wall, DateTimeKind.Unspecified);
        bool dateOnly = Regex.IsMatch(text, @"^\d{4}-\d{2}-\d{2}$");
        if (dateOnly && endOfDate) wall = wall.Date.AddDays(1);
        if (Zone.IsInvalidTime(wall)) throw new FormatException("This local time does not exist in the selected zone (DST transition).");
        if (Zone.IsAmbiguousTime(wall)) throw new FormatException("This local time is ambiguous in the selected zone; specify an explicit offset.");
        var value = new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(wall, Zone));
        return dateOnly && endOfDate ? value.AddTicks(-1) : value;
    }
}

public sealed record TemporalField(string Basis, string Meaning)
{
    public bool CanNormalize(string raw) => Basis == "UTC" || Basis == "Explicit offset or unknown" && TemporalContract.HasOffset(raw);
}

public static class TemporalContract
{
    public static bool HasOffset(string raw) => Regex.IsMatch(raw.Trim(), @"(?:Z|[+-]\d{2}:\d{2})$", RegexOptions.IgnoreCase);
    public static bool TryUtc(string raw, out DateTimeOffset utc)
    {
        bool valid = DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out utc);
        return valid;
    }

    public static TemporalField? Describe(string table, string column, Func<string, string> value)
    {
        bool Is(params string[] names) => names.Contains(column, StringComparer.OrdinalIgnoreCase);
        TemporalField Utc(string meaning) => new("UTC", meaning);
        if (column == "KeyLastWrite") return Utc("Registry key last write; not an individual entry activity time");
        if (column == "ServerKeyLastWrite") return Utc("RDP server key last write; not a proven connection time");
        if (column is "SourceCreatedUtc" or "SourceModifiedUtc" or "SourceAccessedUtc" or "SourceChangedUtc")
            return Utc(column switch
            {
                "SourceCreatedUtc" => "Source file creation; not individual entry activity",
                "SourceModifiedUtc" => "Source file modification; not individual entry activity",
                "SourceChangedUtc" => "Source NTFS metadata change; not individual entry activity",
                _ => "Source file access; not individual entry activity"
            });
        if (table == "prefetch_results" && (Is("LastRun") || Enumerable.Range(1, 7).Any(i => column == "PreviousRun" + i))) return Utc((column == "LastRun" ? "Most recent" : "Previous") + " execution recorded by Prefetch (" + column + ")");
        if (table == "userassist_results" && Is("LastExecution")) return Utc("Last execution recorded by UserAssist");
        if (table == "bam_results" && Is("LastRunTime")) return Utc("Last execution recorded by BAM/DAM");
        if (table == "shimcache_results" && Is("LastModified")) return Utc("Cached file modification; not execution");
        if (table is "shellbags_results" or "native_shellbags_results")
        {
            if (Is("LastWrite", "last_write")) return Utc("Containing (parent) ShellBag registry key last write; not a folder visit time");
            if (Is("CreatedOn", "ModifiedOn", "AccessedOn", "created_on", "modified_on", "accessed_on")) return Utc("Shell item " + column + "; UTC DOS encoding, two-second resolution; not a folder visit time");
        }
        if (table is "opensavemru_results" or "muicache_results" or "usbstor_results" or "typedpaths_results")
        {
            if (Is("KeyLastWrite")) return Utc("Registry key last write; not an individual entry activity time");
            if (table == "usbstor_results" && Is("InstallDate", "FirstInstall", "LastArrival", "LastRemoval")) return Utc("Device " + column);
        }
        if (table == "disk_devices_results" && Is("LastWrite")) return Utc("Disk device registry key last write; not device connection or installation time");
        if (table == "office_mru_results" && Is("LastAccessTime")) return Utc("Office MRU recorded access");
        if (table == "lnk_results" && Is("TargetCreated", "TargetModified", "TargetAccessed", "LnkCreated", "LnkModified", "LnkAccessed")) return Utc(column switch
        {
            "TargetCreated" => "Shortcut target file creation; not shortcut activity",
            "TargetModified" => "Shortcut target file modification; not shortcut activity",
            "TargetAccessed" => "Shortcut target file access; not shortcut activity",
            "LnkCreated" => "Shortcut file creation",
            "LnkModified" => "Shortcut file modification",
            _ => "Shortcut file access"
        });
        if (table == "jumplist_results" && Is("TargetCreated", "TargetModified", "TargetAccessed")) return Utc("JumpList target file " + (column == "TargetCreated" ? "creation" : column == "TargetModified" ? "modification" : "access") + "; not interaction time");
        if (table == "jumplist_results" && Is("LastModified")) return Utc(value("JumplistType") switch
        {
            "Automatic" => "Automatic DestList recorded interaction time",
            "Custom" => "Custom JumpList target file modification; not interaction time",
            _ => "JumpList timestamp; source variant unestablished"
        });
        if (table == "recycle_bin_results" && Is("DeletedDate")) return Utc("Recorded deletion");
        if (table == "user_accounts_results" && Is("LastLogon", "LastPasswordChange", "LastIncorrectPassword", "AccountExpires")) return Utc("Account " + column);
        if (table == "user_profiles_results" && Is("ProfileLoadTime", "ProfileUnloadTime", "DomainProfileLoadTime")) return Utc("Profile " + column);
        if (table == "windows_updates_results" && Is("InstallTime", "LastUpdateTime")) return Utc("Update " + column);
        if (table == "network_interfaces_results" && Is("LeaseObtainedTime", "LeaseTerminatesTime")) return Utc("DHCP " + column);
        if (table == "system_info_results" && column == "PropertyValue" && value("PropertyKey") is "ShutdownTime" or "InstallDate" or "InstallTime") return Utc("System " + value("PropertyKey"));
        if (table == "networklist_results" && Is("FirstConnect", "LastConnect")) return new("Local / zone unknown", "Network profile " + column);
        if (table == "setupapi_results" && Is("InstallDate", "SectionStart", "SectionEnd")) return new("Local / zone unknown", "SetupAPI section " + (column == "SectionEnd" ? "end" : "start"));
        if (table == "installed_programs_results" && Is("InstallDate")) return new("Date only / zone unknown", "Recorded installation date; no clock time established");
        if (table == "scheduled_tasks_results" && Is("RegistrationDate")) return new("Explicit offset or unknown", "Task registration field; not execution");
        if (table == "scheduled_tasks_results" && Is("RegistrationDateRaw")) return new("Original as recorded / zone unestablished", "Original task registration XML value");
        if (table == "amcache_results" && Is("CreatedOn", "ModifiedOn", "StoreModifiedOn"))
            return Utc("AmCache recorded file " + column + "; embedded FILETIME, not execution");
        if (table == "amcache_programs_results" && Is("InstallTime", "UninstallTime"))
            return Utc("AmCache program " + (column == "InstallTime" ? "installation" : "uninstallation") + "; not execution");
        if (table == "amcache_results" && Is("LinkDate") && HasOffset(value(column)))
            return Utc("Executable linker timestamp recorded by AmCache; not execution");
        if (table == "amcache_results" && Is("LinkDate", "LegacyLastWrite")) return new("Unverified", column == "LegacyLastWrite" ? "Legacy Amcache recorded last-write value" : value("TimeField") == "LinkDate" ? "Executable linker field; not execution" : "Amcache timestamp; original variant not established");
        return null;
    }

    public static string RepresentativeColumn(string table, Func<string, string> value)
    {
        string[] candidates = table switch
        {
            "prefetch_results" => new[] { "LastRun", "PreviousRun1", "PreviousRun2", "PreviousRun3", "PreviousRun4", "PreviousRun5", "PreviousRun6", "PreviousRun7" },
            "userassist_results" => new[] { "LastExecution" },
            "bam_results" => new[] { "LastRunTime" },
            "shimcache_results" => new[] { "LastModified" },
            "native_shellbags_results" => new[] { "LastWrite", "ModifiedOn", "CreatedOn", "AccessedOn" },
            "shellbags_results" => new[] { "last_write", "modified_on", "created_on", "accessed_on" },
            "usbstor_results" => new[] { "LastArrival", "LastRemoval", "FirstInstall", "InstallDate" },
            "office_mru_results" => new[] { "LastAccessTime" },
            "rdpclient_results" => new[] { "ServerKeyLastWrite" },
            "lnk_results" => new[] { "LnkModified", "LnkCreated", "TargetModified", "TargetCreated", "TargetAccessed", "LnkAccessed" },
            "jumplist_results" => new[] { "LastModified", "TargetModified", "TargetCreated", "TargetAccessed" },
            "recycle_bin_results" => new[] { "DeletedDate" },
            "user_accounts_results" => new[] { "LastLogon", "LastPasswordChange", "LastIncorrectPassword", "KeyLastWrite", "AccountExpires" },
            "user_profiles_results" => new[] { "ProfileLoadTime", "ProfileUnloadTime", "DomainProfileLoadTime" },
            "network_interfaces_results" => new[] { "LeaseObtainedTime", "LeaseTerminatesTime" },
            "windows_updates_results" => new[] { "InstallTime", "LastUpdateTime" },
            "amcache_results" => new[] { "KeyLastWrite", "LegacyLastWrite", "LinkDate" },
            "amcache_programs_results" => new[] { "InstallTime", "UninstallTime", "KeyLastWrite" },
            "installed_programs_results" => new[] { "InstallDate" },
            "networklist_results" => new[] { "LastConnect", "FirstConnect" },
            "setupapi_results" => new[] { "SectionStart", "InstallDate", "SectionEnd" },
            "scheduled_tasks_results" => new[] { "RegistrationDate", "RegistrationDateRaw" },
            "system_info_results" => new[] { "PropertyValue" },
            _ => Array.Empty<string>()
        };
        foreach (string column in candidates.Concat(new[] { "KeyLastWrite", "SourceModifiedUtc", "SourceCreatedUtc", "SourceAccessedUtc" }))
        {
            string raw = value(column);
            if (Describe(table, column, value) != null && TryUtc(raw, out var parsed) && parsed.Year > 1601)
                return column;
        }
        return "";
    }

    public static string Display(string table, string column, string raw, Func<string, string> value, TemporalDisplay display)
    {
        var field = Describe(table, column, value);
        return field?.CanNormalize(raw) == true ? display.FormatUtc(raw) : raw;
    }
}
