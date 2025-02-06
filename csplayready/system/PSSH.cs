using BinaryStruct;
using static BinaryStruct.ParserBuilder;
using Encoding = System.Text.Encoding;

namespace csplayready.system;

public class PsshStructs
{
    protected static readonly Struct PlayreadyObject = new(
        Int16ul("type"),
        Int16ul("length"),
        Switch("data", ctx => ctx["type"], i => i switch
        {
            1 => UTF16String(string.Empty, ctx => ctx["length"]),
            2 => Bytes(string.Empty, ctx => ctx["length"]),
            3 => Bytes(string.Empty, ctx => ctx["length"]),
            _ => throw new ArgumentOutOfRangeException(nameof(i), i, null)
        })
    );
    
    protected static readonly Struct PlayreadyHeader = new(
        Int32ul("length"),
        Int16ul("record_count"),
        Array("records", Child(string.Empty, PlayreadyObject), ctx => ctx["record_count"])
    );
    
    protected static readonly Struct PsshBox = new(
        Int32ub("length"),
        Const("pssh", "pssh"u8.ToArray()),
        Int32ub("fullbox"),
        Bytes("system_id", 16),
        Int32ub("data_length"),
        Bytes("data", ctx => ctx["data_length"])
    );
}

public class Pssh : PsshStructs
{
    public readonly string[] WrmHeaders;
 
    public Pssh(byte[] data)
    {
        if (data[4..8].SequenceEqual("pssh"u8.ToArray()))
        {
            var psshBox = PsshBox.Parse(data);
            var psshData = (byte[])psshBox["data"];
            
            if (IsUtf16Le(psshData))
            {
                WrmHeaders = [Encoding.Unicode.GetString(data)];
            }
            else
            {
                var playreadyHeader = PlayreadyHeader.Parse(psshData);
                WrmHeaders = ReadPlayreadyObjects(playreadyHeader);
            }
        }
        else
        {
            if (BitConverter.ToInt16(data.AsSpan()[..2]) > 3)
            {
                var playreadyHeader = PlayreadyHeader.Parse(data);
                WrmHeaders = ReadPlayreadyObjects(playreadyHeader);
            }
            else
            {
                var playreadyObject = PlayreadyObject.Parse(data);
                WrmHeaders = [Encoding.Unicode.GetString((byte[])playreadyObject["data"])];
            }
        }
    }

    public Pssh(string b64Data) : this(Convert.FromBase64String(b64Data)) { }

    private static bool IsUtf16Le(byte[] data)
    {
        if (data.Length % 2 != 0)
            return false;

        try
        {
            return Encoding.Unicode.GetString(data).All(c => c >= 0x20 && c <= 0x7E);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
    
    private static string[] ReadPlayreadyObjects(Dictionary<string, object> playreadyHeader)
    {
        var records = (List<object>)playreadyHeader["records"];
        return records.Where(dict => (ushort)((Dictionary<string, object>)dict)["type"] == 1)
            .Select(dict => Convert.ToString(((Dictionary<string, object>)dict)["data"])!)
            .ToArray();
    }
}