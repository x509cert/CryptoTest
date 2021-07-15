using System;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Data.Encryption.Cryptography.Serializers;

// Use this VM's Managed Service Identity
var creds = new DefaultAzureCredential();

// Get the AKV URL from the VM metadata
var kvUri = await SupportKeyVault.GetKeyVaultUrl();

// Create an AKV client
var client = new SecretClient(new Uri(kvUri), creds);

// Pull out the secret used for the key
string secretName = "BaseKey"; 
KeyVaultSecret secret = client.GetSecret(secretName);

// Build a symmetric key
var key = System.Convert.FromBase64String(secret.Value);
PlaintextDataEncryptionKey encryptionKey = new("BaseKey", key);

// Crypto options and parameters
var encryptionSettings = new EncryptionSettings<string>(
    dataEncryptionKey: encryptionKey,
    encryptionType: EncryptionType.Deterministic,
    serializer: StandardSerializerFactory.Default.GetDefaultSerializer<string>()
);

// Now that the crypto is setup, time to connect to SQL using the VM creds


string plaintextString = "This is a secret message";
var ciph = plaintextString.Encrypt(encryptionSettings);
var plain = ciph.Decrypt<string>(encryptionSettings);
Console.Write(plain);
