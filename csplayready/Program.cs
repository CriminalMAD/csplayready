using csplayready.crypto;
using csplayready.device;
using csplayready.system;

using System.CommandLine;
using System.Net;
using System.Text;
using csplayready.license;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;

namespace csplayready;

class Program
{
    private const string Version = "0.5.0";

    private static List<Key>? License(ILogger logger, Device device, Pssh pssh, string server)
    {
        var cdm = Cdm.FromDevice(device);
        logger.LogInformation("Loaded device: {name}", device.GetName());
        
        var sessionId = cdm.Open();

        var wrmHeaders = pssh.GetWrmHeaders();
        if (wrmHeaders.Length == 0)
        {
            logger.LogError("PSSH does not contain any WRM headers");
            return null;
        }
        
        var challenge = cdm.GetLicenseChallenge(sessionId, wrmHeaders.First());
        logger.LogInformation("Created license challenge");

        using HttpClient client = new HttpClient();
        var content = new StringContent(challenge, Encoding.UTF8, "text/xml");

        HttpResponseMessage response = client.PostAsync(server, content).Result;
        logger.LogInformation("Got license message");
        
        var responseBody = response.Content.ReadAsStringAsync().Result;
        
        if (response.StatusCode != HttpStatusCode.OK)
        {
            logger.LogError("Failed to send challenge [{code}]: {error}", (int)response.StatusCode, responseBody);
            return null;
        }
        
        cdm.ParseLicense(sessionId, responseBody);
        logger.LogInformation("License parsed successfully");

        return cdm.GetKeys(sessionId);
    }
    
    public static void Main(string[] args)
    {
        using ILoggerFactory factory = LoggerFactory.Create(builder => builder.AddConsole());
        ILogger logger = factory.CreateLogger("csplayready");
        
        // license

        var license = new Command("license", "Make a License Request to a server using a given PSSH");
        
        var deviceNameArg = new Argument<FileInfo>(name: "prdFile", description: "Device path") { Arity = ArgumentArity.ExactlyOne };
        var psshArg = new Argument<string>(name: "pssh", description: "PSSH") { Arity = ArgumentArity.ExactlyOne };
        var serverArg = new Argument<string>(name: "server", description: "Server URL") { Arity = ArgumentArity.ExactlyOne };
        
        license.AddArgument(deviceNameArg);
        license.AddArgument(psshArg);
        license.AddArgument(serverArg);
        
        license.SetHandler(context =>
        {
            var device = Device.Load(context.ParseResult.GetValueForArgument(deviceNameArg).FullName);
            var pssh = new Pssh(context.ParseResult.GetValueForArgument(psshArg));
            var server = context.ParseResult.GetValueForArgument(serverArg);

            var keys = License(logger, device, pssh, server);
            if (keys == null)
                return;
            
            foreach (var key in keys)
            {
                logger.LogInformation("{keyId}:{key}", key.KeyId.ToHex(), key.RawKey.ToHex());
            }
        });
        
        // test
      
        var test = new Command("test", "Test the CDM code by getting Content Keys for the Tears Of Steel demo on the Playready Test Server");
        
        var deviceNameArg2 = new Argument<FileInfo>(name: "prdFile", description: "Device path") { Arity = ArgumentArity.ExactlyOne };
        
        test.AddArgument(deviceNameArg2);
        
        test.SetHandler(context =>
        {
            var device = Device.Load(context.ParseResult.GetValueForArgument(deviceNameArg2).FullName);
            var pssh = new Pssh(
                "AAADfHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA1xcAwAAAQABAFIDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG" +
                "4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAw" +
                "ADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALg" +
                "AwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwA" +
                "RQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+AD" +
                "wASwBJAEQAPgA0AFIAcABsAGIAKwBUAGIATgBFAFMAOAB0AEcAawBOAEYAVwBUAEUASABBAD0APQA8AC8ASwBJAEQAPgA8AEMASABF" +
                "AEMASwBTAFUATQA+AEsATABqADMAUQB6AFEAUAAvAE4AQQA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaA" +
                "B0AHQAcABzADoALwAvAHAAcgBvAGYAZgBpAGMAaQBhAGwAcwBpAHQAZQAuAGsAZQB5AGQAZQBsAGkAdgBlAHIAeQAuAG0AZQBkAGkA" +
                "YQBzAGUAcgB2AGkAYwBlAHMALgB3AGkAbgBkAG8AdwBzAC4AbgBlAHQALwBQAGwAYQB5AFIAZQBhAGQAeQAvADwALwBMAEEAXwBVAF" +
                "IATAA+ADwAQwBVAFMAVABPAE0AQQBUAFQAUgBJAEIAVQBUAEUAUwA+ADwASQBJAFMAXwBEAFIATQBfAFYARQBSAFMASQBPAE4APgA4" +
                "AC4AMQAuADIAMwAwADQALgAzADEAPAAvAEkASQBTAF8ARABSAE0AXwBWAEUAUgBTAEkATwBOAD4APAAvAEMAVQBTAFQATwBNAEEAVA" +
                "BUAFIASQBCAFUAVABFAFMAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==");
            const string server = "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:2000)";
            
            var keys = License(logger, device, pssh, server);
            if (keys == null)
                return;
            
            foreach (var key in keys)
            {
                logger.LogInformation("{keyId}:{key}", key.KeyId.ToHex(), key.RawKey.ToHex());
            }
        });
        
        // create-device
        
        var createDevice = new Command("create-device", "Create a Playready Device (.prd) file from an ECC private group key (optionally encryption/signing key) and group certificate chain");
        
        var groupKeyOption = new Option<FileInfo>(["-k", "--group_key"], "Device ECC private group key") { IsRequired = true };
        var encryptionKeyOption = new Option<FileInfo>(["-e", "--encryption_key"], "Optional Device ECC private encryption key");
        var signingKeyOption = new Option<FileInfo>(["-s", "--signing_key"], "Optional Device ECC private signing key");
        var groupCertOption = new Option<FileInfo>(["-c", "--group_certificate"], "Device group certificate chain") { IsRequired = true };
        var outputOption = new Option<FileInfo>(["-o", "--output"], "Output file name");

        createDevice.AddOption(groupKeyOption);
        createDevice.AddOption(encryptionKeyOption);
        createDevice.AddOption(signingKeyOption);
        createDevice.AddOption(groupCertOption);
        createDevice.AddOption(outputOption);

        createDevice.SetHandler(context =>
        {
            var groupKey = EccKey.Load(context.ParseResult.GetValueForOption(groupKeyOption)!.FullName);
            
            var encryptionKeyArg = context.ParseResult.GetValueForOption(encryptionKeyOption);
            var encryptionKey = encryptionKeyArg == null ? EccKey.Generate() : EccKey.Load(encryptionKeyArg.FullName);
            
            var signingKeyArg = context.ParseResult.GetValueForOption(signingKeyOption);
            var signingKey = signingKeyArg == null ? EccKey.Generate() : EccKey.Load(signingKeyArg.FullName);
            
            var certificateChain = CertificateChain.Load(context.ParseResult.GetValueForOption(groupCertOption)!.FullName);

            if (!certificateChain.Get(0).GetIssuerKey()!.SequenceEqual(groupKey.PublicBytes()))
            {
                logger.LogError("Group key does not match this certificate");
                return;
            }
            
            var random = new SecureRandom();
            var certId = random.GenerateSeed(16);
            var clientId = random.GenerateSeed(16);

            var leafCert = Certificate.NewLeafCertificate(certId, (uint)certificateChain.GetSecurityLevel()!, clientId, signingKey, encryptionKey, groupKey, certificateChain);
            certificateChain.Prepend(leafCert);
            
            logger.LogInformation("Certificate validity: {validity}", certificateChain.Verify());

            var device = new Device(groupKey, encryptionKey, signingKey, certificateChain);
            
            var outputArg = context.ParseResult.GetValueForOption(outputOption);
            var saveName = outputArg == null ? $"{device.GetName()}.prd" : outputArg.FullName;
            logger.LogInformation("Saving to: {name}", saveName);
            
            device.Dump(saveName);
        });
        
        // reprovision-device
        
        var reprovisionDevice = new Command("reprovision-device", "Reprovision a Playready Device (.prd) by creating a new leaf certificate and new encryption/signing keys");
        
        var deviceNameArg3 = new Argument<FileInfo>(name: "prdFile", description: "Device to reprovision") { Arity = ArgumentArity.ExactlyOne };
        var encryptionKeyOption2 = new Option<FileInfo>(["-e", "--encryption_key"], "Optional Device ECC private encryption key");
        var signingKeyOption2 = new Option<FileInfo>(["-s", "--signing_key"], "Optional Device ECC private signing key");
        var outputOption2 = new Option<string>(["-o", "--output"], "Output file name");
        
        reprovisionDevice.AddArgument(deviceNameArg3);
        reprovisionDevice.AddOption(encryptionKeyOption2);
        reprovisionDevice.AddOption(signingKeyOption2);
        reprovisionDevice.AddOption(outputOption2);
        
        reprovisionDevice.SetHandler(context =>
        {
            var deviceName = context.ParseResult.GetValueForArgument(deviceNameArg3);
            var device = Device.Load(deviceName.FullName);
            
            var encryptionKeyArg = context.ParseResult.GetValueForOption(encryptionKeyOption2);
            var encryptionKey = encryptionKeyArg == null ? EccKey.Generate() : EccKey.Load(encryptionKeyArg.FullName);
            
            var signingKeyArg = context.ParseResult.GetValueForOption(signingKeyOption2);
            var signingKey = signingKeyArg == null ? EccKey.Generate() : EccKey.Load(signingKeyArg.FullName);
            
            // TODO: specifically test this
            if (device.GroupKey == null)
            {
                logger.LogError("Device does not support reprovisioning, re-create it or use a device with a version of 3 or higher");
                return;
            }
            
            device.EncryptionKey = encryptionKey;
            device.SigningKey = signingKey;
            
            var random = new SecureRandom();
            var certId = random.GenerateSeed(16);
            var clientId = random.GenerateSeed(16);

            device.GroupCertificate!.Remove(0);
            
            var leafCert = Certificate.NewLeafCertificate(certId, (uint)device.GroupCertificate.GetSecurityLevel()!, clientId, signingKey, encryptionKey, device.GroupKey, device.GroupCertificate);
            device.GroupCertificate.Prepend(leafCert);
            
            logger.LogInformation("Certificate validity: {validity}", device.GroupCertificate.Verify());
       
            var outputArg = context.ParseResult.GetValueForOption(outputOption2);
            var saveName = outputArg ?? $"{device.GetName()}.prd";
            logger.LogInformation("Saving to: {name}", saveName);
            
            device.Dump(saveName);
        });
        
        // export-device
        
        var exportDevice = new Command("export-device", "Export a Playready Device (.prd) file to a group key and group certificate");
        
        var deviceNameArg4 = new Argument<FileInfo>(name: "prdFile", description: "Device to dump") { Arity = ArgumentArity.ExactlyOne };
        var outputDirOption2 = new Option<string>(["-o", "--output"], "Output directory");
        
        exportDevice.AddArgument(deviceNameArg4);
        exportDevice.AddOption(outputDirOption2);
        
        exportDevice.SetHandler(context =>
        {
            var deviceName = context.ParseResult.GetValueForArgument(deviceNameArg4);
            var device = Device.Load(deviceName.FullName);
            
            var outputDirArg = context.ParseResult.GetValueForOption(outputDirOption2);

            var outDir = outputDirArg ?? Path.GetFileNameWithoutExtension(deviceName.Name);;
            if (Directory.Exists(outDir))
            {
                if (Directory.EnumerateFileSystemEntries(outDir).Any())
                {
                    logger.LogError("Output directory is not empty, cannot overwrite");
                    return;
                }
                
                logger.LogWarning("Output directory already exists, but is empty");
            }
            else
            {
                Directory.CreateDirectory(outDir);
            }
            
            logger.LogInformation("SL{securityLevel} {name}", device.GroupCertificate!.GetSecurityLevel(), device.GetName());
            logger.LogInformation("Saving to: {outDir}", outDir);
            
            device.GroupKey!.Dump(Path.Combine(outDir, "zgpriv.dat"));
            logger.LogInformation("Exported group key as zgpriv.dat");
            
            device.GroupCertificate.Remove(0);
            device.GroupCertificate.Dump(Path.Combine(outDir, "bgroupcert.dat"));
            logger.LogInformation("Exported group certificate to bgroupcert.dat");
        });
        
        var rootCommand = new RootCommand($"csplayready (https://github.com/ready-dl/csplayready) version {Version} Copyright (c) 2025-{DateTime.Now.Year} DevLARLEY");
        
        rootCommand.AddCommand(createDevice);
        rootCommand.AddCommand(exportDevice);
        rootCommand.AddCommand(license);
        rootCommand.AddCommand(reprovisionDevice);
        rootCommand.AddCommand(test);
        
        rootCommand.InvokeAsync(args).Wait();
        
        // TODO:
        //  + cli tool
        //  + TEST V2 DEVICES <---------
        //  + print sizes during provisioning (more logging in general)
        //  + fix weird logging
    }
}
