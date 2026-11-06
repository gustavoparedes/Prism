using System.Data.SQLite;

namespace Prism.Core.Artifacts;

internal static class ArtifactSchema
{

    internal static void EnsureColumns(SQLiteConnection connection, string table,
        params (string Name, string Type)[] columns)
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var command = new SQLiteCommand($"PRAGMA table_info([{table}])", connection))
        using (var reader = command.ExecuteReader())
            while (reader.Read()) existing.Add(reader["name"].ToString()!);
        foreach (var column in columns)
            if (!existing.Contains(column.Name))
            {
                using var alter = new SQLiteCommand($"ALTER TABLE [{table}] ADD COLUMN [{column.Name}] {column.Type}", connection);
                alter.ExecuteNonQuery();
            }
    }
}
