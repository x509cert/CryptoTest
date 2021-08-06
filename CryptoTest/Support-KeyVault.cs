using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

/// <summary>
/// GetKeyVaultUrl 
/// Get's the URL for our Key Vault from the Azure Instance Metadata Service (IMDS) 
/// https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=windows
/// </summary>

public class SupportKeyVault
{
    public static async Task<string> GetKeyVaultUrl()
    {
        const string ImdsServerEp = 
            @"http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text";
        string jsonResult = string.Empty;
        using (var httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.Add("Metadata", "True");
            jsonResult = await httpClient.GetStringAsync(ImdsServerEp);
        }

        return Encoding.UTF8.GetString(System.Convert.FromBase64String(jsonResult));
    }
}