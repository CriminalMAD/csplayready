using Org.BouncyCastle.Asn1.X9;
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

    public static string ToHex(this byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));
}