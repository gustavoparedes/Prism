using System.Data.SQLite;
using Prism.Core.Artifacts;

namespace Prism.Core.Cases;

public sealed partial class PrismCaseReader
{
    public int UpdateLabels(string casePath, IReadOnlyList<(string TableName, long RowId)> targets, string label)
    {
        if (!File.Exists(casePath)) throw new FileNotFoundException("Case file does not exist.", casePath);
        var identities = targets.Distinct().ToArray();
        if (identities.Length == 0) return 0;
        var tables = identities.Select(t => t.TableName).Distinct().ToDictionary(name => name,
            name => ArtifactCatalog.Tables.FirstOrDefault(t => t.TableName == name)
                ?? throw new InvalidOperationException("Unsupported artifact table: " + name));
        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath));
        connection.Open();
        using var transaction = connection.BeginTransaction();
        foreach (var table in tables.Values)
        {
            if (!TableExists(connection, table.TableName) || !ColumnExists(connection, table.TableName, "Label"))
                throw new InvalidOperationException("Artifact table does not support labels: " + table.TableName);
            using var command = new SQLiteCommand($"UPDATE {table.TableName} SET Label=@label WHERE rowid=@id", connection, transaction);
            command.Parameters.AddWithValue("@label", label.Trim());
            command.Parameters.AddWithValue("@id", 0L);
            foreach (var target in identities.Where(t => t.TableName == table.TableName))
            {
                command.Parameters["@id"].Value = target.RowId;
                if (command.ExecuteNonQuery() != 1)
                    throw new InvalidOperationException("A selected artifact no longer exists. No labels were saved.");
            }
        }
        if (!string.IsNullOrWhiteSpace(label)) UpsertLabel(connection, label, transaction);
        transaction.Commit();
        return identities.Length;
    }
}
