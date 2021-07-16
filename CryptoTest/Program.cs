using System;
using System.IO;
using System.Linq;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Data.Encryption.Cryptography.Serializers;
using Microsoft.Data.Encryption.AzureKeyVaultProvider;

// Use this VM's Managed Service Identity
var creds = new DefaultAzureCredential();

// Get the AKV URL from the VM metadata
var kvUri = await SupportKeyVault.GetKeyVaultUrl();

// Create an AKV client
var client = new SecretClient(new Uri(kvUri), creds);

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

// get the data from a plaintext CSV file and build an array of characters
string[] lotrCharacters = File.ReadAllLines(@"c:\\lotr\\lotr.csv");

// Connect to Azure SQL using the VM creds
var sql = new SupportSQL(creds);
sql.Connect();

// read all entries from the CSV file, skip the first line because that's the column headings
for (int i=1; i < lotrCharacters.Length; i++)
{
    string[] elem = lotrCharacters[i].Split(',');
    sql.Insert(
        elem[0],    // name 
        elem[1],    // location 
        elem[2]);   // ssn
}

sql.Close();

string plaintextString = "This is a secret message";
var ciph = plaintextString.Encrypt(encryptionSettings);
var plain = ciph.Decrypt<string>(encryptionSettings);
Console.Write(plain);
