﻿using System.Text.RegularExpressions;
using csplayready.crypto;

using csplayready.constructcs;
using csplayready.system;
using static csplayready.constructcs.ParserBuilder;

namespace csplayready.device;

public class Device(byte version, EccKey? groupKey, EccKey? encryptionKey, EccKey? signingKey, CertificateChain? groupCertificate)
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
    
    public byte Version = version;
    public EccKey? GroupKey = groupKey;
    public EccKey? EncryptionKey = encryptionKey;
    public EccKey? SigningKey = signingKey;
    public CertificateChain? GroupCertificate = groupCertificate;

    public Device() : this(0, null, null, null, null) { }

    public static Device Loads(byte[] bytes)
    {
        var result = Prd.Parse(bytes);
        var data = (Dictionary<string, object>)result["data"];

        Device device = new Device
        {
            Version = (byte)result["version"],
            GroupKey = EccKey.Loads((byte[])data["group_key"]),
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
        return Prd.Build(new Dictionary<string, object>
        {
            { "signature", "PRD"u8.ToArray() },
            { "version", 3 },
            { "data", new Dictionary<string, object>
            {
                { "group_key", GroupKey!.Dumps() },
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
