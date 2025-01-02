using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace csplayready.crypto;

public class EccKey
{
    private static readonly X9ECParameters Curve = ECNamedCurveTable.GetByName("secp256r1");
    private static readonly ECDomainParameters DomainParams = new(Curve.Curve, Curve.G, Curve.N, Curve.H);
    
    public readonly BigInteger PrivateKey;
    public readonly ECPoint PublicKey;

    public EccKey(BigInteger privateKey, ECPoint publicKey)
    {
        PrivateKey = privateKey;
        PublicKey = publicKey;
    }

    public EccKey(BigInteger privateKey)
    {
        PrivateKey = privateKey;
        PublicKey = Curve.G.Multiply(PrivateKey).Normalize();
    }
    
    public static EccKey Generate()
    {
        var eccGenerator = GeneratorUtilities.GetKeyPairGenerator("EC");
        eccGenerator.Init(new ECKeyGenerationParameters(DomainParams, new SecureRandom()));
        
        var eccKeyPair = eccGenerator.GenerateKeyPair();
        return new EccKey(((ECPrivateKeyParameters)eccKeyPair.Private).D, ((ECPublicKeyParameters)eccKeyPair.Public).Q);
    }
    
    public static EccKey Loads(byte[] data, bool verify = true)
    {
        if (data.Length != 32 && data.Length != 96)
        {
            throw new InvalidDataException($"Invalid data length. Expecting 96 or 32 bytes, got {data.Length}");
        }
        
        BigInteger privateKey = new BigInteger(1, data[..32]);
        ECPoint publicKey = Curve.G.Multiply(privateKey).Normalize();

        if (data.Length == 96)
        {
            ECPoint loadedPublicKey = DomainParams.Curve.CreatePoint(
                new BigInteger(1, data[32..64]), 
                new BigInteger(1, data[64..96])
            );
            
            if (verify)
            {
                if (!publicKey.XCoord.Equals(loadedPublicKey.XCoord) || !publicKey.YCoord.Equals(loadedPublicKey.YCoord))
                {
                    throw new InvalidDataException("Derived Public Key does not match loaded Public Key");
                }
            }

            publicKey = loadedPublicKey;
        }
        
        return new EccKey(privateKey, publicKey);
    }

    public static EccKey Load(string path) => Loads(File.ReadAllBytes(path));

    public byte[] Dumps(bool privateOnly = false)
    {
        if (privateOnly)
            return PrivateBytes();
        return PrivateBytes()
            .Concat(PublicBytes()).ToArray();
    }

    public void Dump(string path, bool privateOnly = false) => File.WriteAllBytes(path, Dumps(privateOnly));

    public byte[] PrivateBytes() => PrivateKey.ToRawByteArray();
    
    public byte[] PrivateSha256Digest() => SHA256.HashData(PrivateBytes());
    
    public byte[] PublicBytes()
    {
        return PublicKey.XCoord.ToBigInteger().ToRawByteArray()
            .Concat(PublicKey.YCoord.ToBigInteger().ToRawByteArray())
            .ToArray();
    }
    
    public byte[] PublicSha256Digest() => SHA256.HashData(PublicBytes());
}