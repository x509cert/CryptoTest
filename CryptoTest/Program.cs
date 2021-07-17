using System;
using System.IO;
using System.Text;
using Azure.Identity;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Data.Encryption.Cryptography.Serializers;
using Azure.Security.KeyVault.Secrets;

#region File I/O setup
if (args.Length !=1)
{
    Console.WriteLine("Usage: CryptoTest {e|d}");
    return;
}

bool encrypt = (args[0] == "e") ? true : false;
string fileIn = encrypt ? @"c:\lotr\lotr.csv" : @"c:\lotr\lotr-enc.csv";
string fileOut = encrypt ? @"c:\lotr\lotr-enc.csv" : @"c:\lotr\lotr.csv";

#endregion

#region Setup (Azure login, AKV and crypto settings)

// Use this VM's Managed Service Identity
var creds = new DefaultAzureCredential();

// setup a connection to AKV
var keyVaultUrl = @"https://kv-cryptotest.vault.azure.net/";
var client = new SecretClient(vaultUri: new Uri(keyVaultUrl), credential: creds);

KeyVaultSecret secret = client.GetSecret("CryptoKey");
var key = System.Convert.FromBase64String(secret.Value);
PlaintextDataEncryptionKey encryptionKey = new("DEK", key);

// Crypto options and parameters
var encryptionSettings = new EncryptionSettings<string>(
    dataEncryptionKey: encryptionKey,
    encryptionType: EncryptionType.Deterministic,
    serializer: StandardSerializerFactory.Default.GetDefaultSerializer<string>()
);

#endregion

#region Read from CSV File, encrypt and save the CSV file

// read all entries from the CSV file, and encrypt the last element (SSN)
var recordsIn = File.ReadAllLines(fileIn);
var temp = new StringBuilder();

for (int i = 0; i < recordsIn.Length; i++)
{
    string[] elem = recordsIn[i].Split(',');
    if (elem.Length <= 1) break;

    //headers
    if (i == 0) 
    {
        temp.AppendLine(recordsIn[i]);
    }
    // data
    else
    {
        temp.AppendLine(elem[0] + "," + elem[1] + "," + 
            (encrypt ? Convert.ToBase64String(elem[2].Encrypt(encryptionSettings))
                     : Convert.FromBase64String(elem[2]).Decrypt<string>(encryptionSettings)));
    }
}

File.WriteAllText(fileOut, temp.ToString());

#endregion
