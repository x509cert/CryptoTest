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
    public static void Connect(DefaultAzureCredential creds)
    {
        // Get the OAuth2 token to Azure SQL
        var oauth2TokenSql = creds.GetToken(
                new TokenRequestContext(
                    new[] { "https://database.windows.net/.default" })).Token;

        string connectionString = "Data Source=<AZURE-SQL-SERVERNAME>; Initial Catalog=<DATABASE>;";
        SqlConnection conn = new SqlConnection(connectionString);
        conn.AccessToken = oauth2TokenSql;
        conn.Open();

    }
}
