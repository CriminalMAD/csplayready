using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace csplayready.crypto;

public class ElGamal
{
    private static readonly X9ECParameters Curve = ECNamedCurveTable.GetByName("secp256r1");
    private static readonly ECDomainParameters DomainParams = new(Curve.Curve, Curve.G, Curve.N, Curve.H);

    public static (ECPoint point1, ECPoint point2) Encrypt(ECPoint messagePoint, ECPoint publicKey)
    {
        var random = new SecureRandom();
        var ephemeralKey = new BigInteger(DomainParams.N.BitLength, random);
        
        var point1 = Curve.G.Multiply(ephemeralKey).Normalize();
        var point2 = messagePoint.Add(publicKey.Multiply(ephemeralKey)).Normalize();
        
        return (point1, point2);
    }

    public static ECPoint Decrypt(ECPoint point1, ECPoint point2, BigInteger privateKey)
    {
        var sharedSecret = point1.Multiply(privateKey);
        return point2.Subtract(sharedSecret).Normalize();
    }
}
