using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Dynamic;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace csplayready;

public static class Utils
{
    private static readonly ECCurve Curve = ECNamedCurveTable.GetByName("secp256r1").Curve;
    
    public static byte[] ToFixedByteArray(this BigInteger value) {
        var bytes = value.ToByteArray();
        return bytes.Length switch
        {
            31 => new[] { (byte)0 }.Concat(bytes).ToArray(),
            33 => bytes[1..],
            _ => bytes
        };
    }

    public static byte[] ToBytes(this ECPoint point)
    {
        return point.XCoord.ToBigInteger().ToFixedByteArray()
            .Concat(point.YCoord.ToBigInteger().ToFixedByteArray())
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

    public static string ToHex(this byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));
    
    public static byte[] FromHex(string hex) => Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
}