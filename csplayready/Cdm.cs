using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using csplayready.crypto;
using csplayready.device;
using csplayready.license;
using csplayready.system;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace csplayready;

public class Cdm
{
    private const int MaxNumOfSessions = 16;

    private static readonly byte[] RawWmrmEcc256PubKey = [
        0xc8, 0xb6, 0xaf, 0x16, 0xee, 0x94, 0x1a, 0xad, 0xaa, 0x53, 0x89, 0xb4, 0xaf, 0x2c, 0x10, 0xe3, 
        0x56, 0xbe, 0x42, 0xaf, 0x17, 0x5e, 0xf3, 0xfa, 0xce, 0x93, 0x25, 0x4e, 0x7b, 0x0b, 0x3d, 0x9b, 
        0x98, 0x2b, 0x27, 0xb5, 0xcb, 0x23, 0x41, 0x32, 0x6e, 0x56, 0xaa, 0x85, 0x7d, 0xbf, 0xd5, 0xc6, 
        0x34, 0xce, 0x2c, 0xf9, 0xea, 0x74, 0xfc, 0xa8, 0xf2, 0xaf, 0x59, 0x57, 0xef, 0xee, 0xa5, 0x62
    ];
    private static readonly byte[] RgbMagicConstantZero = [0x7e, 0xe9, 0xed, 0x4a, 0xf7, 0x73, 0x22, 0x4f, 0x00, 0xb8, 0xea, 0x7e, 0xfb, 0x02, 0x7c, 0xbb];

    private readonly ECPoint _wmrmEcc256PubKey;
    private readonly Dictionary<int, Session> _sessions = [];
    
    private readonly CertificateChain _certificateChain;
    private readonly EccKey _encryptionKey;
    private readonly EccKey _signingKey;

    public Cdm(CertificateChain certificateChain, EccKey encryptionKey, EccKey signingKey)
    {
        _certificateChain = certificateChain;
        _encryptionKey = encryptionKey;
        _signingKey = signingKey;
        
        var curve = ECNamedCurveTable.GetByName("secp256r1").Curve;
        _wmrmEcc256PubKey = curve.CreatePoint(
            new BigInteger(1, RawWmrmEcc256PubKey[..32]), 
            new BigInteger(1, RawWmrmEcc256PubKey[32..])
        );
    }

    public static Cdm FromDevice(Device device)
    {
        return new Cdm(device.GroupCertificate!, device.EncryptionKey!, device.SigningKey!);
    }

    public int Open()
    {
        if (_sessions.Count > MaxNumOfSessions)
            throw new TooManySessions($"Too many Sessions open ({MaxNumOfSessions}).");

        var session = new Session(_sessions.Count + 1);
        _sessions[session.Id] = session;

        return session.Id;
    }

    public void Close(int sessionId)
    {
        if (!_sessions.Remove(sessionId))
            throw new InvalidSession($"Session identifier {sessionId} is invalid.");
    }

    private byte[] GetKeyData(Session session)
    {
        (ECPoint point1, ECPoint point2) = Crypto.Ecc256Encrypt(session.XmlKey.GetPoint(), _wmrmEcc256PubKey);
        return point1.ToBytes().Concat(point2.ToBytes()).ToArray();
    }

    private byte[] GetCipherData(Session session)
    {
        var b64Chain = Convert.ToBase64String(_certificateChain.Dumps());
        var body = 
            $"<Data><CertificateChains><CertificateChain>{b64Chain}</CertificateChain></CertificateChains>" +
            $"<Features><Feature Name=\"AESCBC\">\"\"</Feature><REE><AESCBCS></AESCBCS></REE></Features></Data>";

        var ciphertext = Crypto.AesCbcEncrypt(session.XmlKey.AesKey, session.XmlKey.AesIv, Encoding.UTF8.GetBytes(body));
        return session.XmlKey.AesIv.Concat(ciphertext).ToArray();
    }

    private static string GetDigestContent(string wrmHeader, string nonce, string encryptedKey, string encryptedCert)
    {
        TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
        var secondsSinceEpoch = (int)t.TotalSeconds;
        
        return
            "<LA xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols\" Id=\"SignedData\" xml:space=\"preserve\">" +
                "<Version>1</Version>" +
                $"<ContentHeader>{wrmHeader}</ContentHeader>" +
                "<CLIENTINFO>" +
                    "<CLIENTVERSION>10.0.16384.10011</CLIENTVERSION>" +
                "</CLIENTINFO>" +
                $"<LicenseNonce>{nonce}</LicenseNonce>" +
                $"<ClientTime>{secondsSinceEpoch}</ClientTime>" +
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">" +
                    "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>" +
                    "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                        "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">" +
                            "<EncryptionMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256\"></EncryptionMethod>" +
                            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                                "<KeyName>WMRMServer</KeyName>" +
                            "</KeyInfo>" +
                            "<CipherData>" +
                                $"<CipherValue>{encryptedKey}</CipherValue>" +
                            "</CipherData>" +
                        "</EncryptedKey>" +
                    "</KeyInfo>" +
                    "<CipherData>" +
                        $"<CipherValue>{encryptedCert}</CipherValue>" +
                    "</CipherData>" +
                "</EncryptedData>" +
            "</LA>";
    }
    
    private static string GetSignedInfo(string digestValue)
    {
        return
            "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>" +
                "<SignatureMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256\"></SignatureMethod>" +
                "<Reference URI=\"#SignedData\">" +
                    "<DigestMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#sha256\"></DigestMethod>" +
                    $"<DigestValue>{digestValue}</DigestValue>" +
                "</Reference>" +
            "</SignedInfo>";
    }

    public string GetLicenseChallenge(int sessionId, string wrmHeader)
    {
        if (!_sessions.TryGetValue(sessionId, out Session? session))
            throw new InvalidSession($"Session identifier {sessionId} is invalid.");

        session.SigningKey = _signingKey;
        session.EncryptionKey = _encryptionKey;
        
        SecureRandom secureRandom = new SecureRandom();
        
        var randomBytes = new byte[16];
        secureRandom.NextBytes(randomBytes);
        
        var laContent = GetDigestContent(
            wrmHeader, 
            Convert.ToBase64String(randomBytes), 
            Convert.ToBase64String(GetKeyData(session)),
            Convert.ToBase64String(GetCipherData(session))
        );

        var laHash = SHA256.HashData(Encoding.UTF8.GetBytes(laContent));
        var signedInfo = GetSignedInfo(Convert.ToBase64String(laHash));
        var signature = Crypto.Ecc256Sign(session.SigningKey.PrivateKey, Encoding.UTF8.GetBytes(signedInfo));

        return
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
                "<soap:Body>" +
                    "<AcquireLicense xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols\">" +
                        "<challenge>" +
                            "<Challenge xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols/messages\">" +
                                laContent +
                                "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                                    signedInfo +
                                    $"<SignatureValue>{Convert.ToBase64String(signature)}</SignatureValue>" +
                                    "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                                        "<KeyValue>" +
                                            "<ECCKeyValue>" +
                                                $"<PublicKey>{Convert.ToBase64String(session.SigningKey.PublicBytes())}</PublicKey>" +
                                            "</ECCKeyValue>" +
                                        "</KeyValue>" +
                                    "</KeyInfo>" +
                                "</Signature>" +
                            "</Challenge>" +
                        "</challenge>" +
                    "</AcquireLicense>" +
                "</soap:Body>" +
            "</soap:Envelope>";
    }

    private static bool VerifyEncryptionKey(Session session, XmrLicense license)
    {
        var eccKeys = license.GetObject(42);
        if (eccKeys == null)
            throw new InvalidLicense("No ECC public key in license");

        var encryptionKey = (byte[])eccKeys.First()["key"];
        return encryptionKey.SequenceEqual(session.EncryptionKey!.PublicBytes());
    }

    public void ParseLicense(int sessionId, string xmrLicense)
    {
        if (!_sessions.TryGetValue(sessionId, out Session? session))
            throw new InvalidSession($"Session identifier {sessionId} is invalid");

        if (session.EncryptionKey == null || session.SigningKey == null)
            throw new InvalidSession("Cannot parse a license message without first making a license request");

        XDocument doc = XDocument.Parse(xmrLicense);
        XNamespace drmNs = "http://schemas.microsoft.com/DRM/2007/03/protocols";

        foreach (var b64License in doc.Descendants(drmNs + "License").Select(l => l.Value))
        {
            var rawLicense = Convert.FromBase64String(b64License);
            var license = XmrLicense.Loads(rawLicense);

            if (!VerifyEncryptionKey(session, license))
                throw new InvalidLicense("Public encryption key does not match");

            var contentKeys = license.GetObject(10);
            if (contentKeys == null)
                throw new InvalidLicense("License does not contain any content keys");

            var isScalable = license.GetObject(81).Any();
            
            foreach (var contentKey in contentKeys)
            {
                var keyId = (byte[])contentKey["key_id"];
                var keyType = (Key.KeyTypes)contentKey["key_type"];
                var cipherType = (Key.CipherTypes)contentKey["cipher_type"];
                var encryptedKey = (byte[])contentKey["encrypted_key"];
                
                if (!new[] {Key.CipherTypes.Ecc256, Key.CipherTypes.Ecc256WithKz, Key.CipherTypes.Ecc256ViaSymmetric}.Contains(cipherType))
                    throw new InvalidLicense($"Invalid cipher type {cipherType}");

                var viaSymmetric = cipherType == Key.CipherTypes.Ecc256ViaSymmetric;

                (ECPoint point1, ECPoint point2) = (Utils.FromBytes(encryptedKey[..64]), Utils.FromBytes(encryptedKey[64..128]));
                var decrypted = Crypto.Ecc256Decrypt(point1, point2, session.EncryptionKey.PrivateKey).ToBytes();
                var (ci, ck) = (decrypted[..16], decrypted[16..32]);

                if (isScalable)
                {
                    ci = decrypted.Where((x, i) => i % 2 == 0).Take(16).ToArray();
                    ck = decrypted.Where((x, i) => i % 2 == 1).Take(16).ToArray();

                    if (viaSymmetric)
                    {
                        var embeddedRootLicense = encryptedKey[..144];
                        var embeddedLeafLicense = encryptedKey[144..];

                        var rgbKey = Enumerable.Range(0, 16).Select(i => (byte)(ck[i] ^ RgbMagicConstantZero[i])).ToArray();
                        var contentKeyPrime = Crypto.AesEcbEncrypt(ck, rgbKey);

                        var auxiliaryKeys = (List<object>)license.GetObject(81).First()["auxiliary_keys"];
                        var auxKey = (byte[])((Dictionary<string, object>)auxiliaryKeys.First())["key"];

                        var uplinkXKey = Crypto.AesEcbEncrypt(contentKeyPrime, auxKey);
                        var secondaryKey = Crypto.AesEcbEncrypt(ck, embeddedRootLicense[128..]);

                        embeddedLeafLicense = Crypto.AesEcbEncrypt(uplinkXKey, embeddedLeafLicense);
                        embeddedLeafLicense = Crypto.AesEcbEncrypt(secondaryKey, embeddedLeafLicense);

                        (ci, ck) = (embeddedLeafLicense[..16], embeddedLeafLicense[16..]);
                    }
                }
                
                if (!license.CheckSignature(ci))
                    throw new InvalidLicense("License integrity signature does not match");
                
                session.Keys.Add(new Key(keyId, keyType, cipherType, ck));
            }
        }
    }

    public List<Key> GetKeys(int sessionId)
    {
        if (!_sessions.TryGetValue(sessionId, out Session? session))
            throw new InvalidSession($"Session identifier {sessionId} is invalid");

        return session.Keys;
    }
}