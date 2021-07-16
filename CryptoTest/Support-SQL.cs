using System;
using System.Net;
using System.IO;
using System.Data.SqlClient;
using Azure.Identity;
using Azure.Core;

/// <summary>
/// This class supports database access from the VM
/// https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/tutorial-windows-vm-access-sql
/// </summary>

public class SupportSQL
{
    private SqlConnection _conn;
    private string _oauth2TokenSql;

    public SupportSQL(DefaultAzureCredential creds)
    {
        // Get the OAuth2 token to Azure SQL
        _oauth2TokenSql = creds.GetToken(
                new TokenRequestContext(
                    new[] { "https://database.windows.net/.default" })).Token;
    }

    public void Connect() 
    { 
        string connectionString = "Data Source=sql-cryptotest.database.windows.net; Initial Catalog=LoTR;";
        _conn = new SqlConnection(connectionString);
        _conn.AccessToken = _oauth2TokenSql;
        _conn.Open();
    }

    public void Insert(string name, string location, string ssn)
    {
        const string stmt = "INSERT into Characters VALUES (@name, @location, @ssn)";
        if (_conn is null) 
            throw new InvalidDataException("Connection is not set");
        
        SqlCommand cmd = new SqlCommand(stmt, _conn);

        cmd.Parameters.AddWithValue("@name", name);
        cmd.Parameters.AddWithValue("@location", location);
        cmd.Parameters.AddWithValue("@ssn", ssn);

        cmd.ExecuteNonQuery();

        cmd.Dispose();
        cmd = null;
    }

    public void Close()
    {
        if (_conn is null) return;

        _conn.Close();
    }
}
