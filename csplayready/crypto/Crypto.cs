using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace csplayready.crypto;

public static class Crypto
{
    private static readonly X9ECParameters Curve = ECNamedCurveTable.GetByName("secp256r1");
    private static readonly ECDomainParameters DomainParams = new(Curve.Curve, Curve.G, Curve.N, Curve.H);

    public static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] data)
    {
        var cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7");
        var keyParam = new KeyParameter(key);
        var parameters = new ParametersWithIV(keyParam, iv);
        
        cipher.Init(true, parameters);
        return cipher.DoFinal(data);
    }

    public static byte[] AesEcbEncrypt(byte[] key, byte[] data)
    {
        var cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
        var keyParam = new KeyParameter(key);

        cipher.Init(true, keyParam);
        return cipher.DoFinal(data);
    }
    
    public static (ECPoint point1, ECPoint point2) Ecc256Encrypt(ECPoint messagePoint, ECPoint publicKey) => ElGamal.Encrypt(messagePoint, publicKey);
    public static ECPoint Ecc256Decrypt(ECPoint point1, ECPoint point2, BigInteger privateKey) => ElGamal.Decrypt(point1, point2, privateKey);
    
    public static byte[] Ecc256Sign(BigInteger privateKey, byte[] data)
    {
        var signer = new ECDsaSigner();
        
        var hash = SHA256.HashData(data);

        var privateKeyParams = new ECPrivateKeyParameters(privateKey, DomainParams);
        signer.Init(true, privateKeyParams);

        var signature = signer.GenerateSignature(hash);
        return signature[0].ToRawByteArray()
            .Concat(signature[1].ToRawByteArray())
            .ToArray();
    }
    
    public static bool Ecc256Verify(ECPoint publicKey, byte[] data, byte[] signature)
    {
        var signer = new ECDsaSigner();
        
        var publicKeyParams = new ECPublicKeyParameters(publicKey, DomainParams);
        signer.Init(false, publicKeyParams);

        var hash = SHA256.HashData(data);
        var r = new BigInteger(1, signature[..32]);
        var s = new BigInteger(1, signature[32..]);
        
        return signer.VerifySignature(hash, r, s);
    }
}