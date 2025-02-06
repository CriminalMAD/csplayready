using System.Text.Json;
using System.Text.Json.Serialization;
using csplayready.device;
using csplayready.license;
using csplayready.system;
using Microsoft.Extensions.Logging;
using WatsonWebserver;
using WatsonWebserver.Core;
using HttpMethod = WatsonWebserver.Core.HttpMethod;

namespace csplayready.remote;

public class Serve
{
    private readonly string _host;
    private readonly int _port;
    private readonly YamlConfig.ConfigData _config;
    
    private WebserverSettings? _settings;
    private Webserver? _server;

    private readonly ILogger _logger;
    private readonly Dictionary<(string secretKey, string device), Cdm> _cdms = new();
    
    private static readonly JsonSerializerOptions Options = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
    private static readonly JsonContext Context = new(Options);
    
    public Serve(string host, int port, YamlConfig.ConfigData config)
    {
        _host = host;
        _port = port;
        _config = config;
        
        using ILoggerFactory factory = LoggerFactory.Create(builder =>
            builder.SetMinimumLevel(LogLevel.Debug).AddSimpleConsole(options => 
            {
                options.IncludeScopes = false;
                options.SingleLine = true;
                options.TimestampFormat = "HH:mm:ss ";
            }));
        _logger = factory.CreateLogger<Serve>();
    }
    
    public void Run()
    {
        _settings = new WebserverSettings(_host, _port)
        {
            Debug = new WebserverSettings.DebugSettings
            {
                Requests = true
            }
        };

        _server = new Webserver(_settings, DefaultRoute);
        _server.Events.Logger += message => _logger.LogDebug(message);

        _server.Routes.AuthenticateRequest = AuthenticateRequest;
        _server.Events.ExceptionEncountered += ExceptionEncountered;
        
        _server.Routes.PostAuthentication.Parameter.Add(HttpMethod.GET, "/{device}/open", OpenRoute);
        _server.Routes.PostAuthentication.Parameter.Add(HttpMethod.GET, "/{device}/close/{session_id}", CloseRoute);
        _server.Routes.PostAuthentication.Parameter.Add(HttpMethod.POST, "/{device}/get_license_challenge", GetLicenseChallengeRoute);
        _server.Routes.PostAuthentication.Parameter.Add(HttpMethod.POST, "/{device}/parse_license", ParseLicenseRoute);
        _server.Routes.PostAuthentication.Parameter.Add(HttpMethod.POST, "/{device}/get_keys", GetKeysRoute);

        _logger.LogInformation("Starting server on: {prefix}", _settings.Prefix);
        _server.Start();
        
        Console.CancelKeyPress += (_, @event) =>
        {
            @event.Cancel = true;
            _server.Dispose();
            Environment.Exit(0);
        };
        
        _logger.LogInformation("Running... Press CTRL+C to exit.");
        Thread.Sleep(Timeout.Infinite);
    }

    private async Task OpenRoute(HttpContextBase ctx)
    {
        var secretKey = ctx.Request.Headers["X-Secret-Key"]!;
        var deviceName = ctx.Request.Url.Parameters["device"]!;
        var user = _config.users![secretKey];

        var devices = _config.devices!.Where(path => Path.GetFileNameWithoutExtension(path) == deviceName).ToList();
        
        if (devices.Count == 0)
        {
            await SendJsonResponse(ctx, 403, new Message{ message = $"Device '{deviceName}' is not found or you are not authorized to use it." });
            return;
        }

        if (!_cdms.TryGetValue((secretKey, deviceName), out var cdm))
        {
            var device = Device.Load(devices.First());
            cdm = _cdms[(secretKey, deviceName)] = Cdm.FromDevice(device);
        }

        byte[] sessionId;
        try
        {
            sessionId = cdm.Open();
        }
        catch (TooManySessions e)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = e.Message });
            return;
        }
        
        await SendJsonResponse(ctx, 200, new Message
        {
            message = "Success",
            data = new DataMessage
            {
                session_id = sessionId.ToHex(),
                device = new DeviceMessage
                {
                    security_level = cdm.GetSecurityLevel()
                }
            }
        });
    }

    private async Task CloseRoute(HttpContextBase ctx)
    {
        var secretKey = ctx.Request.Headers["X-Secret-Key"]!;
        var deviceName = ctx.Request.Url.Parameters["device"]!;

        var sessionId = Utils.FromHex(ctx.Request.Url.Parameters["session_id"]!);

        if (!_cdms.TryGetValue((secretKey, deviceName), out var cdm))
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"No Cdm session for {deviceName} has been opened yet. No session to close." });
            return;
        }
        
        try
        {
            cdm.Close(sessionId);
        }
        catch (InvalidSession)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"Invalid Session ID '{sessionId.ToHex()}', it may have expired." });
            return;
        }

        await SendJsonResponse(ctx, 200, new Message{ message = $"Successfully closed Session '{sessionId.ToHex()}'." });
    }

    private async Task GetLicenseChallengeRoute(HttpContextBase ctx)
    {
        var secretKey = ctx.Request.Headers["X-Secret-Key"]!;
        var deviceName = ctx.Request.Url.Parameters["device"]!;

        RequestBody jsonBody = JsonSerializer.Deserialize(ctx.Request.DataAsString, Context.RequestBody)!;

        if (jsonBody.session_id is null)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = "Missing required field 'session_id' in JSON body." });
            return;
        }

        var sessionId = Utils.FromHex(jsonBody.session_id);

        if (string.IsNullOrEmpty(jsonBody.init_data))
        {
            await SendJsonResponse(ctx, 400, new Message{ message = "Missing required field 'init_data' in JSON body." });
            return;
        }
        
        if (!_cdms.TryGetValue((secretKey, deviceName), out var cdm))
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"No Cdm session for {deviceName} has been opened yet. No session to use." });
            return;
        }

        var initData = jsonBody.init_data;
        if (!initData.StartsWith("<WRMHEADER"))
        {
            try
            {
                var pssh = new Pssh(initData);
                if (pssh.WrmHeaders.Length > 0)
                    initData = pssh.WrmHeaders.First();
            }
            catch (InvalidPssh e)
            {
                await SendJsonResponse(ctx, 500, new Message{ message = $"Unable to parse base64 PSSH, {e}" });
                return;
            }
        }

        string licenseRequest;
        try
        {
            licenseRequest = cdm.GetLicenseChallenge(sessionId, initData);
        }
        catch (InvalidSession)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"Invalid Session ID '{sessionId.ToHex()}', it may have expired." });
            return;
        }
        catch (Exception e)
        {
            await SendJsonResponse(ctx, 500, new Message{ message = $"Error, {e.Message}" });
            return;
        }
        
        await SendJsonResponse(ctx, 200, new Message
        {
            message = "Success",
            data = new DataMessage
            {
                challenge = licenseRequest
            }
        });
    }

    private async Task ParseLicenseRoute(HttpContextBase ctx)
    {
        var secretKey = ctx.Request.Headers["X-Secret-Key"]!;
        var deviceName = ctx.Request.Url.Parameters["device"]!;

        RequestBody jsonBody = JsonSerializer.Deserialize(ctx.Request.DataAsString, Context.RequestBody)!;

        if (jsonBody.session_id is null)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = "Missing required field 'session_id' in JSON body." });
            return;
        }

        var sessionId = Utils.FromHex(jsonBody.session_id);
        
        if (string.IsNullOrEmpty(jsonBody.license_message))
        {
            await SendJsonResponse(ctx, 400, new Message{ message = "Missing required field 'license_message' in JSON body." });
            return;
        }

        if (!_cdms.TryGetValue((secretKey, deviceName), out var cdm))
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"No Cdm session for {deviceName} has been opened yet. No session to use." });
            return;
        }

        try
        {
            cdm.ParseLicense(sessionId, jsonBody.license_message);
        }
        catch (InvalidSession)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"Invalid Session ID '{sessionId.ToHex()}', it may have expired." });
            return;
        }
        catch (InvalidLicense e)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"Invalid License, {e}" });
            return;
        }
        catch (Exception e)
        {
            await SendJsonResponse(ctx, 500, new Message{ message = $"Error, {e.Message}" });
            return;
        }
        
        await SendJsonResponse(ctx, 200, new Message{ message = "Successfully parsed and loaded the Keys from the License message." });
    }

    private async Task GetKeysRoute(HttpContextBase ctx)
    {
        var secretKey = ctx.Request.Headers["X-Secret-Key"]!;
        var deviceName = ctx.Request.Url.Parameters["device"]!;

        RequestBody jsonBody = JsonSerializer.Deserialize(ctx.Request.DataAsString, Context.RequestBody)!;
        
        if (jsonBody.session_id is null)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = "Missing required field 'session_id' in JSON body." });
            return;
        }

        var sessionId = Utils.FromHex(jsonBody.session_id);
        
        if (!_cdms.TryGetValue((secretKey, deviceName), out var cdm))
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"No Cdm session for {deviceName} has been opened yet. No session to use." });
            return;
        }

        List<Key> keys;
        try
        {
            keys = cdm.GetKeys(sessionId);
        }
        catch (InvalidSession)
        {
            await SendJsonResponse(ctx, 400, new Message{ message = $"Invalid Session ID '{sessionId.ToHex()}', it may have expired." });
            return;
        }
        catch (Exception e)
        {
            await SendJsonResponse(ctx, 500, new Message{ message = $"Error, {e.Message}" });
            return;
        }

        await SendJsonResponse(ctx, 200, new Message
        {
            message = "Success",
            data = new DataMessage
            {
                keys = keys.Select(key => new KeyMessage
                {
                    key_id = key.KeyId.ToHex(),
                    key = key.RawKey.ToHex(),
                    type = (ushort)key.KeyType,
                    cipher_type = (ushort)key.CipherType,
                    key_length = key.RawKey.Length
                }).ToList()
            }
        });
    }
    
    private static async Task DefaultRoute(HttpContextBase ctx)
    {
        await SendJsonResponse(ctx, 200, new Message{ message = "OK" });
    }
    
    private async Task AuthenticateRequest(HttpContextBase ctx)
    {
        var secretKey = ctx.Request.Headers["X-Secret-Key"];
        var path = ctx.Request.Url.RawWithoutQuery;
        var requestIp = ctx.Request.Source.IpAddress;

        if (path != "/")
        {
            if (string.IsNullOrEmpty(secretKey))
            {
                _logger.LogInformation("{requestIp} did not provide authorization.", requestIp);
                await SendJsonResponse(ctx, 401, new Message{ message = "Secret Key is Empty." });
            } else if (!_config.users!.ContainsKey(secretKey))
            {
                _logger.LogInformation("{requestIp} failed authentication with '{secretKey}'.", requestIp, secretKey);
                await SendJsonResponse(ctx, 401, new Message{ message = "Secret Key is Invalid, the Key is case-sensitive." });
            }
        }

        ctx.Response.Headers.Add("Server", $"https://github.com/ready-dl/csplayready serve v{Program.Version}");
    }
    
    private static async Task SendJsonResponse(HttpContextBase ctx, int statusCode, object data)
    {
        ctx.Response.StatusCode = statusCode;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.Send(JsonSerializer.Serialize(data, Context.Message));
    }
    
    private void ExceptionEncountered(object? sender, ExceptionEventArgs args)
    {
        _logger.LogError(args.Exception.ToString());
    }
}