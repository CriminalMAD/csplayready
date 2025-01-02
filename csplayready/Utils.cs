using System.Collections;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace csplayready;

public static class Utils
{
    private static readonly ECCurve Curve = ECNamedCurveTable.GetByName("secp256r1").Curve;
    
    public static byte[] ToRawByteArray(this BigInteger value) {
        var bytes = value.ToByteArray();
        return bytes[0] == 0 ? bytes[1..] : bytes;
    }

    public static byte[] ToBytes(this ECPoint point)
    {
        return point.XCoord.ToBigInteger().ToRawByteArray()
            .Concat(point.YCoord.ToBigInteger().ToRawByteArray())
            .ToArray();
    }

    public static ECPoint FromBytes(byte[] bytes)
    {
        if (bytes.Length != 64)
            throw new ArgumentException("Byte array must be exactly 64 bytes (32 bytes each for X and Y coordinates)");

        ECPoint point = Curve.CreatePoint(
            new BigInteger(1, bytes[..32]), 
            new BigInteger(1, bytes[32..])
        );
        if (!point.IsValid())
            throw new ArgumentException("Point is not valid for the given curve");

        return point;
    }
    
    public static ECPoint ToEcPoint(this byte[] data)
    {
        return ECNamedCurveTable.GetByName("secp256r1").Curve.CreatePoint(
            new BigInteger(1, data[..32]),
            new BigInteger(1, data[32..64])
        );
    }
    
    public static string ToHex(this byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));
    
    public static byte[] HexToBytes(this string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            throw new ArgumentException("Hex string cannot be null or empty.", nameof(hex));

        if (hex.Length % 2 != 0)
            throw new FormatException("Hex string must have an even length.");

        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)((GetHexVal(hex[i * 2]) << 4) + GetHexVal(hex[i * 2 + 1]));
        }
        return bytes;
    }

    private static int GetHexVal(char hex)
    {
        int val = hex;
        return val - (val < 58 ? 48 : val < 97 ? 55 : 87);
    }
    
    public static string FormatBytes(byte[] data)
    {
        StringBuilder builder = new StringBuilder();

        foreach (byte b in data)
        {
            if (b >= 32 && b <= 126)
            {
                builder.Append((char)b);
            }
            else
            {
                builder.AppendFormat("\\x{0:X2}", b);
            }
        }

        return builder.ToString();
    }
    
    public static void PrintObject(object? obj, int indentLevel = 0)
    {
        var indent = new string(' ', indentLevel * 2);

        switch (obj)
        {
            case Dictionary<string, object> dictionary:
                Console.WriteLine($"{indent}Dictionary({dictionary.Count}):");
                foreach (var kvp in dictionary)
                {
                    Console.WriteLine($"{indent}  {kvp.Key}:");
                    PrintObject(kvp.Value, indentLevel + 2);
                }
                break;
            case byte[] bytes:
                Console.WriteLine($"{indent}byte[{bytes.Length}]: \"{FormatBytes(bytes)}\"");
                break;
            case IList list:
                Console.WriteLine($"{indent}List({list.Count}):");
                for (var i = 0; i < list.Count; i++)
                {
                    Console.WriteLine($"{indent} --- {i} ---");
                    PrintObject(list[i], indentLevel + 1);
                }
                break;
            default:
                Console.WriteLine($"{indent}{obj}");
                break;
        }
    }
}