using System.Data;
using Prism.Core.Artifacts;

namespace Prism.Core.Cases;

public sealed partial class PrismCaseReader
{

    private static void AddShimCachePackageFields(DataTable data, ArtifactTable table)
    {
        if (table.TableName != "shimcache_results") return;
        foreach (DataRow row in data.Rows)
        {
            string raw = GetValue(row, "Path", "");
            if (string.IsNullOrWhiteSpace(raw)) raw = GetValue(row, "FilePath", "");
            string[] parts = raw.Split('\t');
            if (parts.Length != 7 || !Hex(parts[0], 8) || !Hex(parts[1], 16) ||
                !Hex(parts[2], 16) || !Hex(parts[3], 4) || string.IsNullOrWhiteSpace(parts[4]) ||
                string.IsNullOrWhiteSpace(parts[5])) continue;

            void Field(string name, string value)
            {
                if (!data.Columns.Contains(name)) data.Columns.Add(name, typeof(string));
                row[name] = value;
            }
            Field("Entry kind", "Windows packaged application (UWP); original Path contains package metadata, not a file path");
            Field("Package name", parts[4]);
            Field("Publisher ID", parts[5]);
            Field("Target architecture", parts[3].ToLowerInvariant() switch
            {
                "8664" => "AMD64 / x64 (0x8664)",
                "014c" => "x86 (0x014c)",
                "aa64" => "ARM64 (0xaa64)",
                "01c4" => "ARM Thumb-2 (0x01c4)",
                _ => "Unresolved architecture code: 0x" + parts[3]
            });
            Field("Resource ID", parts[6].Length == 0 ? "Not specified" : parts[6]);
            Field("Application version (encoded)", parts[1]);
            Field("Target platform version (encoded)", parts[2]);
            Field("Unknown package field (raw)", parts[0]);
            Field("Interpretation", "Packaged application recorded in ShimCache. This entry alone does not establish execution. Version values are preserved as encoded; their byte order has not been validated.");
            Field("Potential_Activity", "Packaged application recorded in ShimCache; execution not established by this entry alone");
        }
    }

    private static bool Hex(string value, int length) =>
        value.Length == length && value.All(Uri.IsHexDigit);
}
