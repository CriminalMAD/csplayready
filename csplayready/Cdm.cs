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
    public static readonly int MaxNumOfSessions = 16;

    private static readonly byte[] RawWmrmEcc256PubKey =
        "c8b6af16ee941aadaa5389b4af2c10e356be42af175ef3face93254e7b0b3d9b982b27b5cb2341326e56aa857dbfd5c634ce2cf9ea74fca8f2af5957efeea562"
            .HexToBytes();
    
    private readonly ECPoint _wmrmEcc256PubKey;

    private readonly Dictionary<int, Session> _sessions = [];
    
    private CertificateChain _certificateChain;
    private EccKey _encryptionKey;
    private EccKey _signingKey;

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
        var body = $"<Data><CertificateChains><CertificateChain>{b64Chain}</CertificateChain></CertificateChains></Data>";

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

    private bool VerifyEncryptionKey(Session session, XmrLicense license)
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
            
            foreach (var contentKey in contentKeys)
            {
                var keyId = (byte[])contentKey["key_id"];
                var keyType = (Key.KeyTypes)contentKey["key_type"];
                var cipherType = (Key.CipherTypes)contentKey["cipher_type"];
                var encryptedKey = (byte[])contentKey["encrypted_key"];
                
                byte[] key;
                byte[] integrityKey;
                
                switch (cipherType)
                {
                    case Key.CipherTypes.Ecc256:
                        (ECPoint point1, ECPoint point2) = (Utils.FromBytes(encryptedKey[..64]), Utils.FromBytes(encryptedKey[64..]));
                        var decrypted = Crypto.Ecc256Decrypt(point1, point2, session.EncryptionKey.PrivateKey).ToBytes();
                        integrityKey = decrypted[..16];
                        key = decrypted[16..32];
                        break;
                    default:
                        throw new InvalidLicense($"Cipher type {cipherType} is not supported");
                }

                if (!license.CheckSignature(integrityKey))
                    throw new InvalidLicense("License integrity signature does not match");
                
                session.Keys.Add(new Key(keyId, keyType, cipherType, key));
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