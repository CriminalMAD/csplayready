using csplayready.constructcs;
using static csplayready.constructcs.ParserBuilder;

namespace csplayready.system;

public class PsshStructs()
{
    private static readonly Struct PlayreadyObject = new(
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
    
    private static readonly Struct PlayreadyHeader = new(
        Int32ul("length"),
        Int16ul("record_count"),
        Array("records", Child("playreadyObject", PlayreadyObject), ctx => ctx["record_count"])
    );
    
    protected static readonly Struct PsshBox = new(
        Int32ub("length"),
        Const("pssh", "pssh"u8.ToArray()),
        Int32ub("fullbox"),
        Bytes("system_id", 16),
        Int32ub("data_length"),
        Child("playreadyHeader", PlayreadyHeader)
    );
}

public class Pssh : PsshStructs
{
    private readonly Dictionary<string, object> _data;
 
    public Pssh(byte[] data)
    {
        _data = PsshBox.Parse(data);
    }
    
    public Pssh(string b64Data)
    {
        var data = Convert.FromBase64String(b64Data);
        _data = PsshBox.Parse(data);
    }

    public string[] GetWrmHeaders()
    {
        var playreadyHeader = (Dictionary<string, object>)_data["playreadyHeader"];
        var records = (List<object>)playreadyHeader["records"];
        return records.Where(dict => (ushort)((Dictionary<string, object>)dict)["type"] == 1)
            .Select(dict => Convert.ToString(((Dictionary<string, object>)dict)["data"])!)
            .ToArray();
    }
}