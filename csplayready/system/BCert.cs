using csplayready.crypto;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using BinaryStruct;
using static BinaryStruct.ParserBuilder;
using Encoding = System.Text.Encoding;

namespace csplayready.system;

public class BCertStructs
{
    protected static readonly Struct DrmBCertBasicInfo = new(
        Bytes("cert_id", 16),
        Int32ub("security_level"),
        Int32ub("flags"),
        Int32ub("cert_type"),
        Bytes("public_key_digest", 32),
        Int32ub("expiration_date"),
        Bytes("client_id", 16)
    );
    
    protected static readonly Struct DrmBCertDomainInfo = new(
        Bytes("service_id", 16),
        Bytes("account_id", 16),
        Int32ub("revision_timestamp"),
        Int32ub("domain_url_length"),
        Bytes("domain_url", ctx => ((uint)ctx["domain_url_length"] + 3) & 0xfffffffc)
    );
    
    protected static readonly Struct DrmBCertPcInfo = new(
        Int32ub("security_version")
    );
    
    protected static readonly Struct DrmBCertDeviceInfo = new(
        Int32ub("max_license"),
        Int32ub("max_header"),
        Int32ub("max_chain_depth")
    );
    
    protected static readonly Struct DrmBCertFeatureInfo = new(
        Int32ub("feature_count"),
        Array("features", Int32ub(string.Empty), ctx => ctx["feature_count"])
    );
    
    protected static readonly Struct DrmBCertKeyInfo = new(
        Int32ub("key_count"),
        Array("cert_keys", Child(string.Empty, new Struct(
            Int16ub("type"),
            Int16ub("length"),
            Int32ub("flags"),
            Bytes("key", ctx => (ushort)ctx["length"] / 8),
            Int32ub("usages_count"),
            Array("usages", Int32ub(string.Empty), ctx => ctx["usages_count"])
        )), ctx => ctx["key_count"])
    );
    
    protected static readonly Struct DrmBCertManufacturerInfo = new(
        Int32ub("flags"),
        Int32ub("manufacturer_name_length"),
        Bytes("manufacturer_name", ctx => ((uint)ctx["manufacturer_name_length"] + 3) & 0xfffffffc),
        Int32ub("model_name_length"),
        Bytes("model_name", ctx => ((uint)ctx["model_name_length"] + 3) & 0xfffffffc),
        Int32ub("model_number_length"),
        Bytes("model_number", ctx => ((uint)ctx["model_number_length"] + 3) & 0xfffffffc)
    );
    
    protected static readonly Struct DrmBCertSignatureInfo = new(
        Int16ub("signature_type"),
        Int16ub("signature_size"),
        Bytes("signature", ctx => ctx["signature_size"]),
        Int32ub("signature_key_size"),
        Bytes("signature_key", ctx => (uint)ctx["signature_key_size"] / 8)
    );
    
    protected static readonly Struct DrmBCertSilverlightInfo = new(
        Int32ub("security_version"),
        Int32ub("platform_identifier")
    );
    
    protected static readonly Struct DrmBCertMeteringInfo = new(
        Bytes("metering_id", 16),
        Int32ub("metering_url_length"),
        Bytes("metering_url", ctx => ((uint)ctx["metering_url_length"] + 3) & 0xfffffffc)
    );
    
    protected static readonly Struct DrmBCertExtDataSignKeyInfo = new(
        Int16ub("key_type"),
        Int16ub("key_length"),
        Int32ub("flags"),
        Bytes("key", ctx => (ushort)ctx["key_length"] / 8)
    );
    
    protected static readonly Struct BCertExtDataRecord = new(
        Int32ub("data_size"),
        Bytes("data", ctx => ctx["data_size"])
    );
    
    protected static readonly Struct DrmBCertExtDataSignature = new(
        Int16ub("signature_type"),
        Int16ub("signature_size"),
        Bytes("signature", ctx => ctx["signature_size"])
    );
    
    protected static readonly Struct BCertExtDataContainer = new(
        Int32ub("record_count"),
        Array("records", Child(string.Empty, BCertExtDataRecord), ctx => ctx["record_count"]),
        Child("signature", DrmBCertExtDataSignature)
    );
    
    protected static readonly Struct DrmBCertServerInfo = new(
        Int32ub("warning_days")
    );
    
    protected static readonly Struct DrmBcertSecurityVersion = new(
        Int32ub("security_version"),
        Int32ub("platform_identifier")
    );
    
    protected static readonly Struct Attribute = new(
        Int16ub("flags"),
        Int16ub("tag"),
        Int32ub("length"),
        Switch("attribute", ctx => ctx["tag"], i => i switch
        {
            1 => Child(string.Empty, DrmBCertBasicInfo),
            2 => Child(string.Empty, DrmBCertDomainInfo),
            3 => Child(string.Empty, DrmBCertPcInfo),
            4 => Child(string.Empty, DrmBCertDeviceInfo),
            5 => Child(string.Empty, DrmBCertFeatureInfo),
            6 => Child(string.Empty, DrmBCertKeyInfo),
            7 => Child(string.Empty, DrmBCertManufacturerInfo),
            8 => Child(string.Empty, DrmBCertSignatureInfo),
            9 => Child(string.Empty, DrmBCertSilverlightInfo),
            10 => Child(string.Empty, DrmBCertMeteringInfo),
            11 => Child(string.Empty, DrmBCertExtDataSignKeyInfo),
            12 => Child(string.Empty, BCertExtDataContainer),
            13 => Child(string.Empty, DrmBCertExtDataSignature),
            14 => Bytes(string.Empty, ctx => (uint)ctx["length"] - 8),
            15 => Child(string.Empty, DrmBCertServerInfo),
            16 => Child(string.Empty, DrmBcertSecurityVersion),
            17 => Child(string.Empty, DrmBcertSecurityVersion),
            _ => Bytes(string.Empty, ctx => (uint)ctx["length"] - 8)
        })
    );
    
    protected static readonly Struct BCert = new(
        Const("signature", "CERT"u8.ToArray()),
        Int32ub("version"),
        Int32ub("total_length"),
        Int32ub("certificate_length"),
        GreedyRange("attributes", Child(string.Empty, Attribute))
    );
    
    protected static readonly Struct BCertChain = new(
        Const("signature", "CHAI"u8.ToArray()),
        Int32ub("version"),
        Int32ub("total_length"),
        Int32ub("flags"),
        Int32ub("certificate_count"),
        GreedyRange("certificates", Child(string.Empty, BCert))
    );
}

public class Certificate(Dictionary<string, object> data) : BCertStructs
{
    public static Certificate Loads(byte[] data)
    {
        return new Certificate(BCert.Parse(data));
    }

    public byte[] Dumps()
    {
        return BCert.Build(data);
    }

    public static Certificate NewLeafCertificate(byte[] certId, uint securityLevel, byte[] clientId, EccKey signingKey, EccKey encryptionKey, EccKey groupKey, CertificateChain parent, uint expiry = 0xFFFFFFFF)
    {
        var basicInfo = new Dictionary<string, object>
        {
            { "cert_id", certId },
            { "security_level", securityLevel },
            { "flags", (uint)0 },
            { "cert_type", (uint)2 },
            { "public_key_digest", signingKey.PublicSha256Digest() },
            { "expiration_date", expiry },
            { "client_id", clientId }
        };
        var basicInfoAttribute = new Dictionary<string, object>
        {
            { "flags", (ushort)1 },
            { "tag", (ushort)1 },
            { "length", (uint)(DrmBCertBasicInfo.Build(basicInfo).Length + 8) },
            { "attribute", basicInfo }
        };
        
        var deviceInfo = new Dictionary<string, object>
        {
            { "max_license", (uint)10240 },
            { "max_header", (uint)15360 },
            { "max_chain_depth", (uint)2 }
        };
        var deviceInfoAttribute = new Dictionary<string, object>
        {
            { "flags", (ushort)1 },
            { "tag", (ushort)4 },
            { "length", (uint)(DrmBCertDeviceInfo.Build(deviceInfo).Length + 8) },
            { "attribute", deviceInfo }
        };
        
        var feature = new Dictionary<string, object>
        {
            { "feature_count", 3 },
            { "features", new List<object>
            {
                // 1,  // Transmitter
                // 2,  // Receiver
                // 3,  // SharedCertificate
                4,  // SecureClock
                // 5, // AntiRollBackClock
                // 6, // ReservedMetering
                // 7, // ReservedLicSync
                // 8, // ReservedSymOpt
                9,  // CRLS (Revocation Lists)
                // 10, // ServerBasicEdition
                // 11, // ServerStandardEdition
                // 12, // ServerPremiumEdition
                13,  // PlayReady3Features
                // 14, // DeprecatedSecureStop
            } },
        };
        var featureAttribute = new Dictionary<string, object>
        {
            { "flags", (ushort)1 },
            { "tag", (ushort)5 },
            { "length", (uint)(DrmBCertFeatureInfo.Build(feature).Length + 8) },
            { "attribute", feature }
        };
        
        var certKeySign = new Dictionary<string, object>
        {
            { "type", (ushort)1 },
            { "length", (ushort)512 },
            { "flags", (uint)0 },
            { "key", signingKey.PublicBytes() },
            { "usages_count", (uint)1 },
            { "usages", new List<object>
            {
                (uint)1  // KEYUSAGE_SIGN
            } },
        };
        var certKeyEncrypt = new Dictionary<string, object>
        {
            { "type", (ushort)1 },
            { "length", (ushort)512 },
            { "flags", (uint)0 },
            { "key", encryptionKey.PublicBytes() },
            { "usages_count", (uint)1 },
            { "usages", new List<object>
            {
                (uint)2  // KEYUSAGE_ENCRYPT_KEY
            } },
        };
        var keyInfo = new Dictionary<string, object>
        {
            { "key_count", (uint)2 },
            { "cert_keys", new List<object>
            {
                certKeySign,
                certKeyEncrypt
            } },
        };
        var keyInfoAttribute = new Dictionary<string, object>
        {
            { "flags", (ushort)1 },
            { "tag", (ushort)6 },
            { "length", (uint)(DrmBCertKeyInfo.Build(keyInfo).Length + 8) },
            { "attribute", keyInfo }
        };

        var manufacturerInfo = parent.Get(0).GetAttribute(7);
        if (manufacturerInfo == null)
            throw new InvalidCertificate("Parent's manufacturer info required for provisioning");
        
        var newBCertContainer = new Dictionary<string, object>
        {
            { "signature", "CERT"u8.ToArray() },
            { "version", (uint)1 },
            { "total_length", (uint)0 },  // filled at a later time
            { "certificate_length", (uint)0 },  // filled at a later time
            { "attributes", new List<object>
            {
                basicInfoAttribute,
                deviceInfoAttribute,
                featureAttribute,
                keyInfoAttribute,
                manufacturerInfo
            } },
        };

        var payload = BCert.Build(newBCertContainer);
        newBCertContainer["certificate_length"] = payload.Length;
        newBCertContainer["total_length"] = payload.Length + 144;

        var signPayload = BCert.Build(newBCertContainer);
        var signature = Crypto.Ecc256Sign(groupKey.PrivateKey, signPayload);

        var signatureInfo = new Dictionary<string, object>
        {
            { "signature_type", (ushort)1 },
            { "signature_size", (ushort)signature.Length },
            { "signature", signature },
            { "signature_key_size", (uint)512 },
            { "signature_key", groupKey.PublicBytes() },
        };
        var signatureInfoAttribute = new Dictionary<string, object>
        {
            { "flags", (ushort)1 },
            { "tag", (ushort)8 },
            { "length", (uint)(DrmBCertSignatureInfo.Build(signatureInfo).Length + 8) },
            { "attribute", signatureInfo }
        };
        ((List<object>)newBCertContainer["attributes"]).Add(signatureInfoAttribute);

        return new Certificate(newBCertContainer);
    }
    
    public Dictionary<string, object>? GetAttribute(ushort type)
    {
        foreach (Dictionary<string, object> attribute in (List<object>)data["attributes"])
        {
            if ((ushort)attribute["tag"] == type)
                return attribute;
        }
        return null;
    }

    public uint? GetSecurityLevel()
    {
        var basicInfo = (Dictionary<string, object>)GetAttribute(1)?["attribute"]!;
        return (uint?)basicInfo["security_level"];
    }

    private static string UnPad(byte[] bytes, byte strip = 0)
    {
        var i = bytes.Length - 1;
        for (; i >= 0; i--)
            if(bytes[i] != strip)
                break;
        return Encoding.UTF8.GetString(bytes[..(i + 1)]);
    }
    
    public string GetName()
    {
        var manufacturerInfo = (Dictionary<string, object>)GetAttribute(7)?["attribute"]!;
        return $"{UnPad((byte[])manufacturerInfo["manufacturer_name"])} {UnPad((byte[])manufacturerInfo["model_name"])} {UnPad((byte[])manufacturerInfo["model_number"])}";
    }

    public byte[]? GetIssuerKey()
    {
        var keyInfoObject = GetAttribute(6);
        if (keyInfoObject == null)
            return null;

        var keyInfoAttribute = (Dictionary<string, object>)keyInfoObject["attribute"];
        return ((List<object>)keyInfoAttribute["cert_keys"])
            .Cast<Dictionary<string, object>>()
            .Where(key => ((List<object>)key["usages"])
                .Cast<uint>()
                .Contains<uint>(6))
            .Select(key => (byte[]?)key["key"])
            .FirstOrDefault();
    }
    
    public byte[]? Verify(byte[] publicKey, int index)
    {
        var signatureObject = GetAttribute(8);
        if (signatureObject == null)
            throw new InvalidCertificate($"No signature object found in certificate {index}");

        var signatureAttribute = (Dictionary<string, object>)signatureObject["attribute"];

        var rawSignatureKey = (byte[])signatureAttribute["signature_key"];
        if (!publicKey.SequenceEqual(rawSignatureKey))
            throw new InvalidCertificate($"Signature keys of certificate {index} do not match");
        
        var signatureKey = ECNamedCurveTable.GetByName("secp256r1").Curve.CreatePoint(
            new BigInteger(1, rawSignatureKey[..32]),
            new BigInteger(1, rawSignatureKey[32..])
        );

        var signPayload = Dumps()[..^(int)(uint)signatureObject["length"]];
        var signature = (byte[])signatureAttribute["signature"];

        if (!Crypto.Ecc256Verify(signatureKey, signPayload, signature))
            throw new InvalidCertificate($"Signature of certificate {index} is not authentic");

        return GetIssuerKey();
    }
    
    public Dictionary<string, object> GetData()
    {
        return data;
    }
}

public class CertificateChain(Dictionary<string, object> data) : BCertStructs
{
    private static readonly byte[] Ecc256MsbCertRootIssuerPubKey =
        "864d61cff2256e422c568b3c28001cfb3e1527658584ba0521b79b1828d936de1d826a8fc3e6e7fa7a90d5ca2946f1f64a2efb9f5dcffe7e434eb44293fac5ab"
            .HexToBytes();
    
    public static CertificateChain Loads(byte[] data)
    {
        return new CertificateChain(BCertChain.Parse(data));
    }

    public static CertificateChain Load(string path)
    {
        var bytes = File.ReadAllBytes(path);
        return Loads(bytes);
    }

    public byte[] Dumps()
    {
        return BCertChain.Build(data);
    }

    public void Dump(string path)
    {
        var bytes = Dumps();
        File.WriteAllBytes(path, bytes);
    }

    public Certificate Get(int index)
    {
        var certificates = (List<object>)data["certificates"];
        return new Certificate((Dictionary<string, object>)certificates[index]);
    }

    public uint Count()
    {
        return (uint)data["certificate_count"];
    }

    public void Append(Certificate bCert)
    {
        data["certificate_count"] = Count() + 1;
        ((List<object>)data["certificates"]).Add(bCert.GetData());
        data["total_length"] = (uint)data["total_length"] + (uint)bCert.Dumps().Length;
    }
    
    public void Prepend(Certificate bCert)
    {
        data["certificate_count"] = Count() + 1;
        ((List<object>)data["certificates"]).Insert(0, bCert.GetData());
        data["total_length"] = (uint)data["total_length"] + (uint)bCert.Dumps().Length;
    }

    public void Remove(int index)
    {
        data["certificate_count"] = Count() - 1;
        data["total_length"] = (uint)data["total_length"] - (uint)Get(index).Dumps().Length;
        ((List<object>)data["certificates"]).RemoveAt(index);
    }
    
    public uint? GetSecurityLevel()
    {
        return Get(0).GetSecurityLevel();
    }

    public string GetName()
    {
        return Get(0).GetName();
    }

    public bool Verify()
    {
        var issuerKey = Ecc256MsbCertRootIssuerPubKey;

        try
        {
            for (var i = (int)(Count() - 1); i >= 0; i--)
            {
                var certificate = Get(i);
                issuerKey = certificate.Verify(issuerKey!, i);

                if (issuerKey == null && i != 0)
                {
                    throw new InvalidCertificate($"Certificate {i} is not valid");
                }
            }
        }
        catch (InvalidCertificate e)
        {
            throw new InvalidCertificateChain("CertificateChain is not valid", e);
        }
        
        return true;
    }
    
    public Dictionary<string, object> GetData()
    {
        return data;
    }
}