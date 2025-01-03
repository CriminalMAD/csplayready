using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using BinaryStruct;
using static BinaryStruct.ParserBuilder;

namespace csplayready.license;

public class XmrLicenseStructs
{
    private static readonly Struct PlayEnablerType = new(
        Bytes("player_enabler_type", 16)
    );
    
    private static readonly Struct DomainRestrictionObject = new(
        Bytes("account_id", 16),
        Int32ub("revision")
    );
    
    private static readonly Struct IssueDateObject = new(
        Int32ub("issue_date")
    );
    
    private static readonly Struct RevInfoVersionObject = new(
        Int32ub("sequence")
    );
    
    private static readonly Struct SecurityLevelObject = new(
        Int16ub("minimum_security_level")
    );
    
    private static readonly Struct EmbeddedLicenseSettingsObject = new(
        Int16ub("indicator")
    );
    
    private static readonly Struct EccKeyObject = new(
        Int16ub("curve_type"),
        Int16ub("key_length"),
        Bytes("key", ctx => ctx["key_length"])
    );
    
    private static readonly Struct SignatureObject = new(
        Int16ub("signature_type"),
        Int16ub("signature_data_length"),
        Bytes("signature_data", ctx => ctx["signature_data_length"])
    );
    
    private static readonly Struct ContentKeyObject = new(
        Bytes("key_id", 16),
        Int16ub("key_type"),
        Int16ub("cipher_type"),
        Int16ub("key_length"),
        Bytes("encrypted_key", ctx => ctx["key_length"])
    );
    
    private static readonly Struct RightsSettingsObject = new(
        Int16ub("rights")
    );
    
    private static readonly Struct OutputProtectionLevelRestrictionObject = new(
        Int16ub("minimum_compressed_digital_video_opl"),
        Int16ub("minimum_uncompressed_digital_video_opl"),
        Int16ub("minimum_analog_video_opl"),
        Int16ub("minimum_digital_compressed_audio_opl"),
        Int16ub("minimum_digital_uncompressed_audio_opl")
    );
    
    private static readonly Struct ExpirationRestrictionObject = new(
        Int32ub("begin_date"),
        Int32ub("end_date")
    );
    
    private static readonly Struct RemovalDateObject = new(
        Int32ub("removal_date")
    );
    
    private static readonly Struct UplinkKidObject = new(
        Bytes("uplink_kid", 16),
        Int16ub("chained_checksum_type"),
        Int16ub("chained_checksum_length"),
        Bytes("chained_checksum", ctx => ctx["chained_checksum_length"])
    );
    
    private static readonly Struct AnalogVideoOutputConfigurationRestriction = new(
        Bytes("video_output_protection_id", 16),
        Bytes("binary_configuration_data", ctx => (uint)ctx["length"] - 24)
    );
    
    private static readonly Struct DigitalVideoOutputRestrictionObject = new(
        Bytes("video_output_protection_id", 16),
        Bytes("binary_configuration_data", ctx => (uint)ctx["length"] - 24)
    );
    
    private static readonly Struct DigitalAudioOutputRestrictionObject = new(
        Bytes("audio_output_protection_id", 16),
        Bytes("binary_configuration_data", ctx => (uint)ctx["length"] - 24)
    );
    
    private static readonly Struct PolicyMetadataObject = new(
        Bytes("metadata_type", 16),
        Bytes("policy_data", ctx => (uint)ctx["length"] - 24)
    );
    
    private static readonly Struct SecureStopRestrictionObject = new(
        Bytes("metering_id", 16)
    );
    
    private static readonly Struct MeteringRestrictionObject = new(
        Bytes("metering_id", 16)
    );
    
    private static readonly Struct ExpirationAfterFirstPlayRestrictionObject = new(
        Int32ub("seconds")
    );
    
    private static readonly Struct GracePeriodObject = new(
        Int32ub("grace_period")
    );
    
    private static readonly Struct SourceIdObject = new(
        Int32ub("source_id")
    );
    
    private static readonly Struct AuxiliaryKey = new(
        Int32ub("location"),
        Bytes("key", 16)
    );
    
    private static readonly Struct AuxiliaryKeysObject = new(
        Int16ub("count"),
        Array("auxiliary_keys", Child(string.Empty, AuxiliaryKey), ctx => ctx["count"])
    );
    
    private static readonly Struct UplinkKeyObject3 = new(
        Bytes("uplink_key_id", 16),
        Int16ub("chained_length"),
        Bytes("checksum", ctx => ctx["chained_length"]),
        Int16ub("count"),
        Array("entries", Int32ub(string.Empty), ctx => ctx["count"])
    );
    
    private static readonly Struct CopyEnablerObject = new(
        Bytes("copy_enabler_type", 16)
    );
    
    private static readonly Struct CopyCountRestrictionObject = new(
        Int32ub("count")
    );
    
    private static readonly Struct MoveObject = new(
        Int32ub("minimum_move_protection_level")
    );

    private static readonly Struct XmrObject = new(
        Int16ub("flags"),
        Int16ub("type"),
        Int32ub("length"),
        Switch("data", ctx => ctx["type"], i => i switch 
        {
            0x0005 => Child(string.Empty, OutputProtectionLevelRestrictionObject),
            0x0008 => Child(string.Empty, AnalogVideoOutputConfigurationRestriction),
            0x000a => Child(string.Empty, ContentKeyObject),
            0x000b => Child(string.Empty, SignatureObject),
            0x000d => Child(string.Empty, RightsSettingsObject),
            0x0012 => Child(string.Empty, ExpirationRestrictionObject),
            0x0013 => Child(string.Empty, IssueDateObject),
            0x0016 => Child(string.Empty, MeteringRestrictionObject),
            0x001a => Child(string.Empty, GracePeriodObject),
            0x0022 => Child(string.Empty, SourceIdObject),
            0x002a => Child(string.Empty, EccKeyObject),
            0x002c => Child(string.Empty, PolicyMetadataObject),
            0x0029 => Child(string.Empty, DomainRestrictionObject),
            0x0030 => Child(string.Empty, ExpirationAfterFirstPlayRestrictionObject),
            0x0031 => Child(string.Empty, DigitalAudioOutputRestrictionObject),
            0x0032 => Child(string.Empty, RevInfoVersionObject),
            0x0033 => Child(string.Empty, EmbeddedLicenseSettingsObject),
            0x0034 => Child(string.Empty, SecurityLevelObject),
            0x0037 => Child(string.Empty, MoveObject),
            0x0039 => Child(string.Empty, PlayEnablerType),
            0x003a => Child(string.Empty, CopyEnablerObject),
            0x003b => Child(string.Empty, UplinkKidObject),
            0x003d => Child(string.Empty, CopyCountRestrictionObject),
            0x0050 => Child(string.Empty, RemovalDateObject),
            0x0051 => Child(string.Empty, AuxiliaryKeysObject),
            0x0052 => Child(string.Empty, UplinkKeyObject3),
            0x005a => Child(string.Empty, SecureStopRestrictionObject),
            0x0059 => Child(string.Empty, DigitalVideoOutputRestrictionObject),
            _ => Child(string.Empty, () => XmrObject!)
        })
    );

    protected static readonly Struct XmrLicense = new(
        Const("signature", "XMR\0"u8.ToArray()),
        Int32ub("xmr_version"),
        Bytes("rights_id", 16),
        GreedyRange("containers", Child(string.Empty, XmrObject))
    );
}

public class XmrLicense(Dictionary<string, object> data) : XmrLicenseStructs
{
    public static XmrLicense Loads(byte[] data)
    {
        return new XmrLicense(XmrLicense.Parse(data));
    }

    public byte[] Dumps()
    {
        return XmrLicense.Build(data);
    }
    
    private static Dictionary<string, object> Locate(Dictionary<string, object> container)
    {
        while (true)
        {
            var flags = (ushort)container["flags"];
            if (flags != 2 && flags != 3) return container;
            
            container = (Dictionary<string, object>)container["data"];
        }
    }

    public IEnumerable<Dictionary<string, object>> GetObject(ushort type)
    {
        foreach (Dictionary<string, object> obj in (List<object>)data["containers"])
        {
            var container = Locate(obj);
            if ((ushort)container["type"] == type)
                yield return (Dictionary<string, object>)container["data"];
        }
    }

    public bool CheckSignature(byte[] integrityKey)
    {
        var cmac = new CMac(new AesEngine());
        cmac.Init(new KeyParameter(integrityKey));

        var signatureObject = GetObject(11).FirstOrDefault();
        if (signatureObject == null)
            throw new InvalidLicense("License does not contain a signature object");
        
        var message = Dumps()[..^((ushort)signatureObject["signature_data_length"] + 12)];
        cmac.BlockUpdate(message, 0, message.Length);
        
        var result = new byte[cmac.GetMacSize()];
        cmac.DoFinal(result, 0);

        return result.SequenceEqual((byte[])signatureObject["signature_data"]);
    }
    
    public Dictionary<string, object> GetData()
    {
        return data;
    }
}