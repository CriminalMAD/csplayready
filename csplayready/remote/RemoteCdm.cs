using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using csplayready.device;
using csplayready.license;

namespace csplayready.remote;

public class RemoteCdm
{
    private readonly int _securityLevel;
    private readonly string _host;
    private readonly string _deviceName;

    private readonly HttpClient _client;
    
    private static readonly JsonSerializerOptions Options = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
    private static readonly JsonContext Context = new(Options);
    
    public RemoteCdm(int securityLevel, string host, string secret, string deviceName)
    {
        _securityLevel = securityLevel;
        _host = host.EndsWith('/') ? host[..^1] : host;
        _deviceName = deviceName;

        _client = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = true
        });
        
        _client.DefaultRequestHeaders.Add("X-Secret-Key", secret);
    }
    
    public static RemoteCdm FromDevice(Device device)
    {
        throw new NotImplementedException("You cannot load a RemoteCdm from a local Device file.");
    }

    public byte[] Open()
    {
        var response = _client.GetAsync($"{_host}/{_deviceName}/open").Result;
        Message jsonBody = JsonSerializer.Deserialize(response.Content.ReadAsStringAsync().Result, Context.Message)!;
        
        if (response.StatusCode != HttpStatusCode.OK)
            throw new Exception($"Cannot Open CDM Session, {jsonBody.message} [{response.StatusCode}]");

        if (jsonBody.data!.device!.security_level != _securityLevel)
            throw new DeviceMismatch("The Security Level specified does not match the one specified in the API response.");

        return Utils.FromHex(jsonBody.data!.session_id!);
    }

    public void Close(byte[] sessionId)
    {
        var response = _client.GetAsync($"{_host}/{_deviceName}/close/{sessionId.ToHex()}").Result;
        Message jsonBody = JsonSerializer.Deserialize(response.Content.ReadAsStringAsync().Result, Context.Message)!;
        
        if (response.StatusCode != HttpStatusCode.OK)
            throw new Exception($"Cannot Close CDM Session, {jsonBody.message} [{response.StatusCode}]");
    }

    public string GetLicenseChallenge(byte[] sessionId, string wrmHeader)
    {
        var contentString = JsonSerializer.Serialize(new RequestBody
        {
            session_id = sessionId.ToHex(),
            init_data = wrmHeader
        }, Context.RequestBody);
        
        var content = new StringContent(contentString, Encoding.UTF8, "application/json");
        var response = _client.PostAsync($"{_host}/{_deviceName}/get_license_challenge", content).Result;
        
        Message jsonBody = JsonSerializer.Deserialize(response.Content.ReadAsStringAsync().Result, Context.Message)!;
        
        if (response.StatusCode != HttpStatusCode.OK)
            throw new Exception($"Cannot get Challenge, {jsonBody.message} [{response.StatusCode}]");

        return jsonBody.data!.challenge!;
    }

    public void ParseLicense(byte[] sessionId, string xmrLicense)
    {
        var contentString = JsonSerializer.Serialize(new RequestBody
        {
            session_id = sessionId.ToHex(),
            license_message = xmrLicense
        }, Context.RequestBody);
        
        var content = new StringContent(contentString, Encoding.UTF8, "application/json");
        var response = _client.PostAsync($"{_host}/{_deviceName}/parse_license", content).Result;
        
        Message jsonBody = JsonSerializer.Deserialize(response.Content.ReadAsStringAsync().Result, Context.Message)!;
        
        if (response.StatusCode != HttpStatusCode.OK)
            throw new Exception($"Cannot parse License, {jsonBody.message} [{response.StatusCode}]");
    }

    public List<Key> GetKeys(byte[] sessionId)
    {
        var contentString = JsonSerializer.Serialize(new RequestBody{ session_id = sessionId.ToHex() }, Context.RequestBody);
        
        var content = new StringContent(contentString, Encoding.UTF8, "application/json");
        var response = _client.PostAsync($"{_host}/{_deviceName}/get_keys", content).Result;
        
        Message jsonBody = JsonSerializer.Deserialize(response.Content.ReadAsStringAsync().Result, Context.Message)!;
        
        if (response.StatusCode != HttpStatusCode.OK)
            throw new Exception($"Cannot get Keys, {jsonBody.message} [{response.StatusCode}]");

        return jsonBody.data!.keys!.Select(key => new Key(
            keyId: Convert.FromHexString(key.key_id!), 
            keyType: (Key.KeyTypes)(key.type ?? 0), 
            cipherType: (Key.CipherTypes)(key.cipher_type ?? 0), 
            rawKey: Convert.FromHexString(key.key!))
        ).ToList();
    }
}