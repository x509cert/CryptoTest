using System;
using System.IO;
using System.Data;
using Microsoft.Data.SqlClient;
using Azure.Identity;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Data.Encryption.Cryptography.Serializers;
using Azure.Core;
using Microsoft.Data.Encryption.AzureKeyVaultProvider;

#region Setup (Azure login, AKV and crypto settings)
// Use this VM's Managed Service Identity
var creds = new DefaultAzureCredential();

// Get the AKV URL from the VM metadata
var kvUri = await SupportKeyVault.GetKeyVaultUrl();

// Get the key from AKV
EncryptionKeyStoreProvider azureKeyProvider = new AzureKeyVaultKeyStoreProvider(creds);
KeyEncryptionKey keyEncryptionKey = new KeyEncryptionKey("KEK", kvUri, azureKeyProvider);
ProtectedDataEncryptionKey encryptionKey = new ProtectedDataEncryptionKey("DEK", keyEncryptionKey);

// Crypto options and parameters
var encryptionSettings = new EncryptionSettings<string>(
    dataEncryptionKey: encryptionKey,
    encryptionType: EncryptionType.Deterministic,
    serializer: StandardSerializerFactory.Default.GetDefaultSerializer<string>()
);

#endregion

#region Read from CSV File and built up the DataTable
// read all entries from the CSV file, and encrypt the last element (SSN)
var records = File.ReadAllLines(@"c:\\lotr\\lotr.csv");
DataTable dt = new DataTable();

for (int i = 0; i < records.Length; i++)
{
    string[] elem = records[i].Split(',');
    if (elem.Length <= 1) break;

    if (i == 0) //headers
    {
        dt.Columns.Add(elem[0], typeof(string));
        dt.Columns.Add(elem[1], typeof(string));
        dt.Columns.Add(elem[2], typeof(Byte[]));
    }
    else
    {
        dt.Rows.Add();
        dt.Rows[i - 1].SetField("name", elem[0]);
        dt.Rows[i - 1].SetField("location", elem[1]);
        dt.Rows[i - 1].SetField("ssn", elem[2].Encrypt(encryptionSettings));
    }
}

dt.AcceptChanges();

#endregion

#region SQL

var connectionString = "Data Source=sql-cryptotest.database.windows.net; Initial Catalog=LoTR;Column Encryption Setting=enabled";
using (var connection = new SqlConnection(connectionString))
{
    var token = creds.GetToken(
            new TokenRequestContext(
                new[] { "https://database.windows.net/.default" })).Token;

    connection.AccessToken = token;

    connection.Open();

    using (var bulkCopy = new SqlBulkCopy(connection, SqlBulkCopyOptions.AllowEncryptedValueModifications, null))
    {
        string[] dbColumns = { "name", "location", "ssn" };

        foreach (var column in dbColumns)
            bulkCopy.ColumnMappings.Add(column, column);

        bulkCopy.DestinationTableName = "[dbo].[Peoples2]";

        bulkCopy.WriteToServer(dt);
    }
}


//// Connect to Azure SQL using the VM creds
//var sql = new SupportSQL(creds);
//sql.Connect();
//sql.BulkCopy(encryptedRecords.ToString());



//sql.Close();

#endregion

//string plaintextString = "This is a secret message";
//var ciph = plaintextString.Encrypt(encryptionSettings);
//var plain = ciph.Decrypt<string>(encryptionSettings);
//Console.Write(plain);
