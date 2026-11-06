using System.Data;
using Prism.Core.Artifacts;

namespace Prism.Core.Cases;

public sealed partial class PrismCaseReader
{
    private static void AddTypedPathsDisplay(DataTable data, ArtifactTable table)
    {
        if (table.TableName != "typedpaths_results" || !data.Columns.Contains("TypedPath")) return;
        foreach (DataRow row in data.Rows)
        {
            string text = GetValue(row, "TypedPath", "");
            int nul = text.IndexOf('\0');
            if (nul >= 0)
            {
                foreach (string column in new[] { "TypedPathOriginal", "TypedPathStatus" })
                    if (!data.Columns.Contains(column)) data.Columns.Add(column, typeof(string));
                if (string.IsNullOrEmpty(GetValue(row, "TypedPathOriginal", ""))) row["TypedPathOriginal"] = text;
                row["TypedPath"] = text[..nul];
                row["TypedPathStatus"] = "Legacy stored text split at NUL for display; original registry bytes/type were not stored";
            }
            if (data.Columns.Contains("TypedPathOriginal"))
                row["TypedPathOriginal"] = GetValue(row, "TypedPathOriginal", "").Replace("\0", "\\0");
        }
    }
}
