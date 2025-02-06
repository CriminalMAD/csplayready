using System.Text.Json.Serialization;
using YamlDotNet.Serialization;

namespace csplayready.remote;

public class YamlConfig
{
    public class ConfigData
    {
        public List<string>? devices { get; set; }
        public Dictionary<string, UserInfo>? users { get; set; }
    }

    public class UserInfo
    {
        public string? username { get; set; }
        public List<string>? devices { get; set; }
    }
}

[YamlStaticContext]
[YamlSerializable(typeof(YamlConfig.ConfigData))]
[YamlSerializable(typeof(YamlConfig.UserInfo))]
public partial class YamlContext;

public class Message
{
    public string? message { get; set; }
    public DataMessage? data { get; set; }
}

public class DataMessage
{
    public List<KeyMessage>? keys { get; set; }
    public string? challenge { get; set; }
    public string? session_id  { get; set; }
    public DeviceMessage? device { get; set; }
}

public class KeyMessage
{
    public string? key_id { get; set; }
    public string? key { get; set; }
    public int? type { get; set; }
    public int? cipher_type { get; set; }
    public int? key_length { get; set; }
}

public class DeviceMessage
{
    public uint? security_level { get; set; }
}

public class RequestBody
{
    public string? session_id { get; set; }
    public string? init_data { get; set; }
    public string? license_message { get; set; }
}

[JsonSerializable(typeof(Message))]
[JsonSerializable(typeof(RequestBody))]
public partial class JsonContext : JsonSerializerContext;
