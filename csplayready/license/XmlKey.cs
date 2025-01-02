using csplayready.crypto;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace csplayready.license;

public class XmlKey
{
    private static readonly ECCurve Curve = ECNamedCurveTable.GetByName("secp256r1").Curve;
    
    private readonly BigInteger _sharedX;
    private readonly BigInteger _sharedY;

    public readonly byte[] AesIv;
    public readonly byte[] AesKey;
    
    public XmlKey()
    {
        var sharedPoint = EccKey.Generate();
        _sharedX = sharedPoint.PublicKey.XCoord.ToBigInteger();
        _sharedY = sharedPoint.PublicKey.YCoord.ToBigInteger();

        var sharedXBytes = _sharedX.ToRawByteArray();
        AesIv = sharedXBytes[..16];
        AesKey = sharedXBytes[16..];
    }

    public ECPoint GetPoint()
    {
        return Curve.CreatePoint(_sharedX, _sharedY);
    }
}
