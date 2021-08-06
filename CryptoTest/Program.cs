using System;
using System.Linq;
using System.IO;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System.Collections.Generic;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Data.Encryption.Cryptography.Serializers;

#region Setup connection to Azure and access AKV
// Get Azure connection creds, this could be 
// a VM's Managed Service Identity
// or the current logged in user
var creds = new DefaultAzureCredential();

// Get the AKV URL from the VM metadata & create an AKV client
var kvUri = @"https://kv-cryptotest.vault.azure.net/";
var client = new SecretClient(new Uri(kvUri), creds);

#endregion

#region Get all the versions of a specific secret
// The name of our root secret, this has 1-n versions
string secretName = "CryptoKey4";
var rootKeys = new Dictionary<string, EncryptionSettings<string>>();

// this is the newest key
var keyLatestDate = new DateTime(0);
var keyLatestVersion = String.Empty;

// Retrieve all versions of this secret from AKV
foreach (SecretProperties secret in client.GetPropertiesOfSecretVersions(secretName))
{
    try
    {
        KeyVaultSecret secretWithValue = client.GetSecret(secret.Name, secret.Version);

        var name = secret.Name;
        var version = secretWithValue.Properties.Version;
        var rootkey = secretWithValue.Value;

        var key = System.Convert.FromBase64String(rootkey);
        PlaintextDataEncryptionKey encryptionKey = new(version, key);
        var encryptionSettings = new EncryptionSettings<string>(
            dataEncryptionKey: encryptionKey,
            encryptionType: EncryptionType.Randomized,
            serializer: StandardSerializerFactory.Default.GetDefaultSerializer<string>()
        );

        rootKeys.Add(version, encryptionSettings);

        // updated the latest key
        var created = secretWithValue.Properties.CreatedOn;
        if (created > keyLatestDate)
        {
            keyLatestDate = created.Value.DateTime;
            keyLatestVersion = version;
        }

    } 
    catch (Azure.RequestFailedException ex)
    {
        //Console.WriteLine($"Error {ex.Status}");
    }
}

Console.WriteLine($"{secretName} has {rootKeys.Count} versions:");
foreach (var k in rootKeys)
    Console.WriteLine("  " + k.Key);

Console.WriteLine($"\nNewest key:\n  {keyLatestVersion}");

#endregion

Console.WriteLine("\n[C] to create new encrypted files\n[D] to decrypt all exist files\n[E] to decrypt and re-encrypt with latest key.");
var keyPress = Console.ReadKey();

#region Create new encrypted files, with a random key selected from AKV

const string rootFolder = @"c:\temp\enc\";
const string suffix = ".enc.txt";
const string DELIM = ":";

if (keyPress.Key == ConsoleKey.C)
{
    Console.WriteLine("\nWriting new files with random keys");

    // create N random files, encrypted with random keys from AKV
    for (int i = 0; i < 7; i++)
    {
        // select a key at random to simulate old, outdated keys
        var rnd = new Random();
        var whichKey = rnd.Next(0, rootKeys.Count);
        var encSetting = rootKeys.ElementAt(whichKey);

        string plaintextString = $"TopSecret - using version {encSetting.Key} - {DateTime.Now}!";
        var ciph = plaintextString.Encrypt(encSetting.Value);
        var result = encSetting.Key + DELIM + Convert.ToBase64String(ciph);

        var filename = rootFolder + Guid.NewGuid().ToString().Split('-')[0] + suffix;
        File.WriteAllText(filename, result);
    }

    Console.WriteLine();
}

#endregion

#region Read and decrypt the ciphertext from each file

if (keyPress.Key == ConsoleKey.D || keyPress.Key == ConsoleKey.E)
{
    // get all the encrypted files, pull out the key version ID and use it to get the decryption key
    var encFiles = Directory.EnumerateFiles(rootFolder, "*" + suffix, SearchOption.AllDirectories);
    var fileCount = encFiles.Count();
    Console.WriteLine($"\n{fileCount} encrypted files.");

    foreach (string currentFile in encFiles)
    {
        Console.WriteLine("  File: " + currentFile);

        var ciphBlob = File.ReadAllText(currentFile).Split(DELIM);
        var keyVersion = ciphBlob[0];
        var ciphertext = Convert.FromBase64String(ciphBlob[1]);

        var encSetting = rootKeys[keyVersion];
        var plain = ciphertext.Decrypt<string>(encSetting);

        Console.WriteLine("    Key Version: " + keyVersion);
        Console.WriteLine("    Plaintext:   " + plain);

        // write decrypted data back out with new key
        if (keyPress.Key == ConsoleKey.E)
        {
            if (keyVersion.CompareTo(keyLatestVersion) == 0)
            {
                Console.WriteLine("    Skipping re-encryption, already using latest key.");
            }
            else
            {
                var latest = rootKeys[keyLatestVersion];
                Console.WriteLine($"    Re-encrypt from {keyVersion} to {keyLatestVersion}");
                var ciph = plain.Encrypt(latest);
                var result = keyLatestVersion + DELIM + Convert.ToBase64String(ciph);

                File.WriteAllText(currentFile, result);
            }
        }

        Console.WriteLine();
    }
}

#endregion

