using System.Data.SQLite;
using Prism.Core.Artifacts;

namespace Prism.Core.Cases;

public sealed partial class PrismCaseReader
{
    public IReadOnlyDictionary<string,int> LoadSystemProfileCounts(string casePath)
    {
        using var db=new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));db.Open();
        return CountSystemProfile(db);
    }
    private static IReadOnlyDictionary<string,int> CountSystemProfile(SQLiteConnection db)
    {
        var counts=new Dictionary<string,int>();
        foreach(var view in SystemProfileCatalog.Views)
        {
            var table=ProfileTable(db,view);
            counts[view.Id]=table==null?0:CountRows(db,table);
        }
        return counts;
    }
    public ArtifactRowsResult LoadSystemProfileRows(string casePath,string viewId,TemporalDisplay display)
    {
        var view=SystemProfileCatalog.Get(viewId);
        using var db=new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));db.Open();
        var table=ProfileTable(db,view);
        if(table==null)return new(Array.Empty<ResultPreviewRow>(),0);
        int count=CountRows(db,table);
        return new(ReadRows(db,table,count,display).OrderByDescending(row=>row.TimestampUtc).ThenBy(row=>row.RowId).ToArray(),count);
    }
    private static ArtifactTable? ProfileTable(SQLiteConnection db,SystemProfileView view)
    {
        var table=ArtifactCatalog.Tables.Single(t=>t.DisplayName==view.ArtifactName);
        if(!TableExists(db,table.TableName))return null;
        if(view.FilterColumn==null)return table;
        if(!ColumnExists(db,table.TableName,view.FilterColumn))return null;
        string Quote(string text)=>"'"+text.Replace("'","''")+"'";
        string column="["+view.FilterColumn+"]";
        var conditions=new List<string>();
        if(!string.IsNullOrWhiteSpace(table.WhereClause))conditions.Add("("+table.WhereClause+")");
        if(view.Values!=null)conditions.Add(column+" COLLATE NOCASE IN ("+string.Join(",",view.Values.Select(Quote))+")");
        if(view.Prefixes!=null)conditions.Add("("+string.Join(" OR ",view.Prefixes.Select(prefix=>column+" LIKE "+Quote(prefix+"%")))+")");
        if(view.ExcludedFragments!=null)conditions.AddRange(view.ExcludedFragments.Select(fragment=>column+" NOT LIKE "+Quote("%"+fragment+"%")));
        return table with {WhereClause=string.Join(" AND ",conditions)};
    }
}
