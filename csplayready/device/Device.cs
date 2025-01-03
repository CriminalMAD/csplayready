using csplayready.crypto;
using csplayready.system;

using BinaryStruct;
using static BinaryStruct.ParserBuilder;

using System.Text.RegularExpressions;

namespace csplayready.device;

public class Device(EccKey? groupKey, EccKey? encryptionKey, EccKey? signingKey, CertificateChain? groupCertificate)
{
    private static readonly Struct PrdV2 = new(
        Int32ub("group_certificate_length"),
        Bytes("group_certificate", ctx => ctx["group_certificate_length"]),
        Bytes("encryption_key", 96),
        Bytes("signing_key", 96)
    );
    
    private static readonly Struct PrdV3 = new(
        Bytes("group_key", 96),
        Bytes("encryption_key", 96),
        Bytes("signing_key", 96),
        Int32ub("group_certificate_length"),
        Bytes("group_certificate", ctx => ctx["group_certificate_length"])
    );

    private static readonly Struct Prd = new(
        Const("signature", "PRD"u8.ToArray()),
        Int8ub("version"),
        Switch("data", ctx => ctx["version"], i => i switch
        {
            2 => Child(string.Empty, PrdV2),
            3 => Child(string.Empty, PrdV3),
            _ => throw new InvalidDataException($"Unknown PRD version {i}")
        })
    );

    private const byte Version = 3;
    public EccKey? GroupKey = groupKey;
    public EccKey? EncryptionKey = encryptionKey;
    public EccKey? SigningKey = signingKey;
    public CertificateChain? GroupCertificate = groupCertificate;

    private Device() : this(null, null, null, null) { }

    public static Device Loads(byte[] bytes)
    {
        var result = Prd.Parse(bytes);
        var data = (Dictionary<string, object>)result["data"];

        Device device = new Device
        {
            GroupKey = data.TryGetValue("group_key", out var value) ? EccKey.Loads((byte[])value) : null,
            EncryptionKey = EccKey.Loads((byte[])data["encryption_key"]),
            SigningKey = EccKey.Loads((byte[])data["signing_key"]),
            GroupCertificate = CertificateChain.Loads((byte[])data["group_certificate"])
        };
        return device;
    }

    public static Device Load(string path)
    {
        return Loads(File.ReadAllBytes(path));
    }
    
    public byte[] Dumps()
    {
        if (GroupKey == null)
            throw new OutdatedDevice("Cannot dump a v2 device, re-create it or use a Device with a version of 3 or higher");
        
        return Prd.Build(new Dictionary<string, object>
        {
            { "signature", "PRD"u8.ToArray() },
            { "version", Version },
            { "data", new Dictionary<string, object>
            {
                { "group_key", GroupKey.Dumps() },
                { "encryption_key", EncryptionKey!.Dumps() },
                { "signing_key", SigningKey!.Dumps() },
                { "group_certificate_length", GroupCertificate!.Dumps().Length },
                { "group_certificate", GroupCertificate!.Dumps() },
            }}
        });
    }

    public void Dump(string path)
    {
        File.WriteAllBytes(path, Dumps());
    }

    public string? GetName()
    {
        if (GroupCertificate == null) return null;
        var name = $"{GroupCertificate!.GetName()}_sl{GroupCertificate!.GetSecurityLevel()}";
        return Regex.Replace(name, @"[^a-zA-Z0-9_\- ]", "").Replace(" ", "_").ToLower();
    }
}
