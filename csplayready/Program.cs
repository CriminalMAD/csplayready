using System.Text;
using System.Xml.Linq;
using csplayready.device;
using csplayready.system;

namespace csplayready;

class Program
{
    private static readonly XNamespace DrmNs = "http://schemas.microsoft.com/DRM/2007/03/protocols";
    
    public static IEnumerable<string> GetAllLicenses(XDocument doc)
    {
        return doc.Descendants(DrmNs + "License").Select(l => l.Value);
    }
    
    public static void Main(string[] args)
    {
        
        /*using Org.BouncyCastle.Math;
        using Org.BouncyCastle.Math.EC;
        using Org.BouncyCastle.Utilities.Encoders;*/
        /*EccKey key = EccKey.Generate();
        Console.WriteLine("Private key: " + key.PrivateKey);

        EccKey messagePoint = EccKey.Generate();
        Console.WriteLine("plaintext: " + messagePoint.PublicBytes().ToHex());

        (ECPoint e1, ECPoint e2) = Crypto.Ecc256Encrypt(messagePoint.PublicKey, key.PublicKey);
        Console.WriteLine("encrypted 1: " + e1.XCoord.ToBigInteger() + " " + e1.YCoord.ToBigInteger());
        Console.WriteLine("encrypted 2: " + e2.XCoord.ToBigInteger() + " " + e2.YCoord.ToBigInteger());

        var bytes = e1.ToBytes().Concat(e2.ToBytes()).ToArray();
        Console.WriteLine("encrypted: " + bytes.ToHex());

        var curve = ECNamedCurveTable.GetByName("secp256r1");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

        var l1 = Utils.FromBytes(bytes[..64], domainParams);
        var l2 = Utils.FromBytes(bytes[64..], domainParams);

        ECPoint decryptedE = Crypto.Ecc256Decrypt(e1, e2, key.PrivateKey);
        Console.WriteLine("decrypted e: " + decryptedE.ToBytes().ToHex());

        ECPoint decryptedL = Crypto.Ecc256Decrypt(l1, l2, key.PrivateKey);
        Console.WriteLine("decrypted l: " + decryptedL.ToBytes().ToHex());*/
        /*
        using constructcs;
        using static constructcs.ParserBuilder;

        string text = "AAADfHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA1xcAwAAAQABAFIDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4" +
                      "AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC" +
                      "8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0A" +
                      "C4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAx" +
                      "ADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgB" +
                      "PAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgA0AFIAcABsAGIAKwBUAGIATgBFAFMAOAB0AEcAawBOAEYAVwBUAEUASA" +
                      "BBAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AEsATABqADMAUQB6AFEAUAAvAE4AQQA9ADwALwBDAEgAR" +
                      "QBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHAAcgBvAGYAZgBpAGMAaQBhAGwAcwBpAHQA" +
                      "ZQAuAGsAZQB5AGQAZQBsAGkAdgBlAHIAeQAuAG0AZQBkAGkAYQBzAGUAcgB2AGkAYwBlAHMALgB3AGkAbgBkAG8AdwBzAC4" +
                      "AbgBlAHQALwBQAGwAYQB5AFIAZQBhAGQAeQAvADwALwBMAEEAXwBVAFIATAA+ADwAQwBVAFMAVABPAE0AQQBUAFQAUgBJAE" +
                      "IAVQBUAEUAUwA+ADwASQBJAFMAXwBEAFIATQBfAFYARQBSAFMASQBPAE4APgA4AC4AMQAuADIAMwAwADQALgAzADEAPAAvA" +
                      "EkASQBTAF8ARABSAE0AXwBWAEUAUgBTAEkATwBOAD4APAAvAEMAVQBTAFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8" +
                      "AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==";

        var pssh = new Pssh(text);
        Console.WriteLine(string.Join(", ", pssh.GetWrmHeaders()));*/
        /*
        using csplayready.license;

        const string licenseString = "WE1SAAAAAANtHSY9EpvluoRHZaggdNEeAAMAAQAAAaYAAwACAAAAMgABAA0AAAAKAAEAAAAzAAAACgABAAEAMgAAAAwAAABMAAEANAAAAAoH0AACAAQAAABeAAEABQAAABIBkAEOAJYAZABkAAMABwAAACQAAQAIAAAAHJGhg9eD4K9Lstrmn5ELN3JA7wcAAAIANgAAACAAAAA5AAAAGB/ZIbbM7TVAjUvccXYNQ+kAAwAJAAAA8gABAAoAAACeHl06aWdatUKc9+vZTOADAQABAAMAgFpnAzpVEpVCWcpDHRv8K7dVTfDu1KVeLfpb4kvFWbD9hcNEDSpse946LHZRYsFw19sPnhs5sOnJe+Q/zy4EoX+BG9zZc6WCetrPhb/vKC2tGvwJrCqHFUE5DM82g5WjIV96cf61OQtSLMvrIT0dJmIV5YKfi5RTeAAb2kOj+AE7AAAAKgAAAEwAAQBA8yyUn9LQzBQonmbYcnuUQ3iZMVxdjP3VDDi5goFt3ofTWrFdOT4MXi0YKUE4G/zk8Xp6gPHkJjG8XKsM6mTbPQABAAsAAAAcAAEAELeiTV1WtdIiQPmFZnF1JN4=";

        var data = Convert.FromBase64String(licenseString);
        var license = XmrLicense.Loads(data);

        Utils.PrintObject(license.GetObject(10));*/
        /*
        using csplayready.crypto;
        using csplayready.device;
        using csplayready.system;
        using Org.BouncyCastle.Security;

        var encryptionKey = EccKey.Load(@"C:\Users\titus\RiderProjects\csplayready\csplayready\hisense\encr.dat");
        var signingKey = EccKey.Load(@"C:\Users\titus\RiderProjects\csplayready\csplayready\hisense\sig.dat");

        var groupKey = EccKey.Load(@"C:\Users\titus\RiderProjects\csplayready\csplayready\hisense\zgpriv.dat");
        var certificateChain = CertificateChain.Load(@"C:\Users\titus\RiderProjects\csplayready\csplayready\hisense\bgroupcert.dat");

        if (!certificateChain.Get(0).GetIssuerKey()!.SequenceEqual(groupKey.PublicBytes()))
            throw new InvalidCertificateChain("Group key does not match this certificate");

        var random = new SecureRandom();
        var certId = random.GenerateSeed(16);
        var clientId = random.GenerateSeed(16);

        var leafCert = Certificate.NewLeafCertificate(certId, (uint)certificateChain.GetSecurityLevel()!, clientId, signingKey, encryptionKey, groupKey, certificateChain);
        certificateChain.Prepend(leafCert);

        Console.WriteLine("Valid: " + certificateChain.Verify());

        var device = new Device(3, groupKey, encryptionKey, signingKey, certificateChain);
        device.Dump("fourth_cs_device.prd");*/

        // TODO: 
        //  + make Utils class better
        //  + more exceptions
        //  + cli tool
        
        var device = Device.Load(args[0]);
        var cdm = Cdm.FromDevice(device);
        var sessionId = cdm.Open();

        var pssh = new Pssh(
            "AAADfHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA1xcAwAAAQABAFIDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4Ac" +
            "wA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANw" +
            "AvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA" +
            "8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABB" +
            "AEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgA0A" +
            "FIAcABsAGIAKwBUAGIATgBFAFMAOAB0AEcAawBOAEYAVwBUAEUASABBAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AE" +
            "sATABqADMAUQB6AFEAUAAvAE4AQQA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHA" +
            "AcgBvAGYAZgBpAGMAaQBhAGwAcwBpAHQAZQAuAGsAZQB5AGQAZQBsAGkAdgBlAHIAeQAuAG0AZQBkAGkAYQBzAGUAcgB2AGkAYwBlAHMA" +
            "LgB3AGkAbgBkAG8AdwBzAC4AbgBlAHQALwBQAGwAYQB5AFIAZQBhAGQAeQAvADwALwBMAEEAXwBVAFIATAA+ADwAQwBVAFMAVABPAE0AQ" +
            "QBUAFQAUgBJAEIAVQBUAEUAUwA+ADwASQBJAFMAXwBEAFIATQBfAFYARQBSAFMASQBPAE4APgA4AC4AMQAuADIAMwAwADQALgAzADEAPA" +
            "AvAEkASQBTAF8ARABSAE0AXwBWAEUAUgBTAEkATwBOAD4APAAvAEMAVQBTAFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8AC8ARAB" +
            "BAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==");

        var wrmHeaders = pssh.GetWrmHeaders();
        var challenge = cdm.GetLicenseChallenge(sessionId, wrmHeaders[0]);

        Console.WriteLine(challenge);

        using HttpClient client = new HttpClient();
        const string url = "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:2000)";
        var content = new StringContent(challenge, Encoding.UTF8, "text/xml");
        
        HttpResponseMessage response = client.PostAsync(url, content).Result;
        response.EnsureSuccessStatusCode();
        var responseBody = response.Content.ReadAsStringAsync().Result;
        
        Console.WriteLine(responseBody);
        
        cdm.ParseLicense(sessionId, responseBody);

        foreach (var key in cdm.GetKeys(sessionId))
        {
            Console.WriteLine($"{key.KeyId.ToHex()}:{key.RawKey.ToHex()}");
        }
        
        cdm.Close(sessionId);
    }
}
