using csplayready.crypto;
using csplayready.device;
using csplayready.system;
using csplayready.license;

using System.CommandLine;
using System.Net;
using System.Text;
using csplayready.remote;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace csplayready;

class Program
{
    public const string Version = "0.5.5";

    private static List<Key>? License(ILogger logger, Device device, Pssh pssh, string server)
    {
        var cdm = Cdm.FromDevice(device);
        logger.LogInformation("Loaded device: {name}", device.GetName());
        
        var sessionId = cdm.Open();

        if (pssh.WrmHeaders.Length == 0)
        {
            logger.LogError("PSSH does not contain any WRM headers");
            return null;
        }
        
        var challenge = cdm.GetLicenseChallenge(sessionId, pssh.WrmHeaders.First());
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
        using ILoggerFactory factory = LoggerFactory.Create(builder =>
                builder.AddSimpleConsole(options =>
                {
                    options.IncludeScopes = false;
                    options.SingleLine = true;
                    options.TimestampFormat = "HH:mm:ss ";
                }));
        ILogger logger = factory.CreateLogger("csplayready");

        // license

        var license = new Command("license", "Make a License Request to a server using a given PSSH");
        
        var deviceNameArg = new Argument<FileInfo>(name: "prdFile", description: "Device path") { Arity = ArgumentArity.ExactlyOne };
        var psshArg = new Argument<string>(name: "pssh", description: "PSSH") { Arity = ArgumentArity.ExactlyOne };
        var serverArg = new Argument<string>(name: "server", description: "Server URL") { Arity = ArgumentArity.ExactlyOne };
        
        license.AddArgument(deviceNameArg);
        license.AddArgument(psshArg);
        license.AddArgument(serverArg);
        
        license.SetHandler((deviceName, pssh, server) =>
        {
            var device = Device.Load(deviceName.FullName);

            var keys = License(logger, device, new Pssh(pssh), server);
            if (keys == null) return;
            
            foreach (var key in keys)
            {
                logger.LogInformation("{keyId}:{key}", key.KeyId.ToHex(), key.RawKey.ToHex());
            }
        }, deviceNameArg, psshArg, serverArg);
        
        // test
      
        var test = new Command("test", "Test the CDM code by getting Content Keys for the Tears Of Steel demo on the Playready Test Server");
        
        var deviceNameArg2 = new Argument<FileInfo>(name: "prdFile", description: "Device path") { Arity = ArgumentArity.ExactlyOne };
        var encryptionTypeOption = new Option<string>(["-c", "--ckt"], description: "Content key encryption type", getDefaultValue: () => "aesctr").FromAmong("aesctr", "aescbc");
        var securityLevelOption = new Option<string>(["-sl", "--security_level"], description: "Minimum security level", getDefaultValue: () => "2000" ).FromAmong("150", "2000", "3000");
        
        test.AddArgument(deviceNameArg2);
        test.AddOption(encryptionTypeOption);
        test.AddOption(securityLevelOption);
        
        test.SetHandler((deviceName, encryptionType, securityLevel) =>
        {
            var device = Device.Load(deviceName.FullName);
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

            var server = $"https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:{securityLevel},ckt:{encryptionType})";
            
            var keys = License(logger, device, pssh, server);
            if (keys == null) return;
            
            foreach (var key in keys)
            {
                logger.LogInformation("{keyId}:{key}", key.KeyId.ToHex(), key.RawKey.ToHex());
            }
        }, deviceNameArg2, encryptionTypeOption, securityLevelOption);
        
        // create-device
        
        var createDevice = new Command("create-device", "Create a Playready Device (.prd) file from an ECC private group key (optionally encryption/signing key) and group certificate chain");
        
        var groupKeyOption = new Option<FileInfo>(["-k", "--group_key"], "Device ECC private group key") { IsRequired = true };
        var encryptionKeyOption = new Option<FileInfo?>(["-e", "--encryption_key"], "Optional Device ECC private encryption key");
        var signingKeyOption = new Option<FileInfo?>(["-s", "--signing_key"], "Optional Device ECC private signing key");
        var groupCertOption = new Option<FileInfo>(["-c", "--group_certificate"], "Device group certificate chain") { IsRequired = true };
        var outputOption = new Option<FileInfo?>(["-o", "--output"], "Output file name");

        createDevice.AddOption(groupKeyOption);
        createDevice.AddOption(encryptionKeyOption);
        createDevice.AddOption(signingKeyOption);
        createDevice.AddOption(groupCertOption);
        createDevice.AddOption(outputOption);

        createDevice.SetHandler((groupKeyName, encryptionKeyName, signingKeyName, groupCertName, output) =>
        {
            var groupKey = EccKey.Load(groupKeyName.FullName);
            var certificateChain = CertificateChain.Load(groupCertName.FullName);
            
            var encryptionKey = encryptionKeyName == null ? EccKey.Generate() : EccKey.Load(encryptionKeyName.FullName);
            var signingKey = signingKeyName == null ? EccKey.Generate() : EccKey.Load(signingKeyName.FullName);

            if (!certificateChain.Get(0).GetIssuerKey()!.SequenceEqual(groupKey.PublicBytes()))
            {
                logger.LogError("Group key does not match this certificate");
                return;
            }
            
            var certId = Crypto.GetRandomBytes(16);
            var clientId = Crypto.GetRandomBytes(16);

            var leafCert = Certificate.NewLeafCertificate(certId, (uint)certificateChain.GetSecurityLevel()!, clientId, signingKey, encryptionKey, groupKey, certificateChain);
            certificateChain.Prepend(leafCert);
            
            logger.LogInformation("Certificate validity: {validity}", certificateChain.Verify());

            var device = new Device(groupKey, encryptionKey, signingKey, certificateChain);
            
            var saveName = output == null ? $"{device.GetName()}.prd" : output.FullName;
            logger.LogInformation("Saving to: {name}", saveName);
            
            device.Dump(saveName);
        }, groupKeyOption, encryptionKeyOption, signingKeyOption, groupCertOption, outputOption);
        
        // reprovision-device
        
        var reprovisionDevice = new Command("reprovision-device", "Reprovision a Playready Device (.prd) by creating a new leaf certificate and new encryption/signing keys");
        
        var deviceNameArg3 = new Argument<FileInfo>(name: "prdFile", description: "Device to reprovision") { Arity = ArgumentArity.ExactlyOne };
        var encryptionKeyOption2 = new Option<FileInfo?>(["-e", "--encryption_key"], "Optional Device ECC private encryption key");
        var signingKeyOption2 = new Option<FileInfo?>(["-s", "--signing_key"], "Optional Device ECC private signing key");
        var outputOption2 = new Option<string?>(["-o", "--output"], "Output file name");
        
        reprovisionDevice.AddArgument(deviceNameArg3);
        reprovisionDevice.AddOption(encryptionKeyOption2);
        reprovisionDevice.AddOption(signingKeyOption2);
        reprovisionDevice.AddOption(outputOption2);
        
        reprovisionDevice.SetHandler((deviceName, encryptionKeyName, signingKeyName, output) =>
        {
            var device = Device.Load(deviceName.FullName);
            
            var encryptionKey = encryptionKeyName == null ? EccKey.Generate() : EccKey.Load(encryptionKeyName.FullName);
            var signingKey = signingKeyName == null ? EccKey.Generate() : EccKey.Load(signingKeyName.FullName);
            
            if (device.GroupKey == null)
            {
                logger.LogError("Device does not support reprovisioning, re-create it or use a device with a version of 3 or higher");
                return;
            }
            
            device.EncryptionKey = encryptionKey;
            device.SigningKey = signingKey;
            
            var certId = Crypto.GetRandomBytes(16);
            var clientId = Crypto.GetRandomBytes(16);

            device.GroupCertificate!.Remove(0);
            
            var leafCert = Certificate.NewLeafCertificate(certId, (uint)device.GroupCertificate.GetSecurityLevel()!, clientId, signingKey, encryptionKey, device.GroupKey, device.GroupCertificate);
            device.GroupCertificate.Prepend(leafCert);
            
            logger.LogInformation("Certificate validity: {validity}", device.GroupCertificate.Verify());
       
            var saveName = output ?? $"{device.GetName()}.prd";
            logger.LogInformation("Saving to: {name}", saveName);
            
            device.Dump(saveName);
        }, deviceNameArg3, encryptionKeyOption2, signingKeyOption2, outputOption2);
        
        // export-device
        
        var exportDevice = new Command("export-device", "Export a Playready Device (.prd) file to a group key and group certificate");
        
        var deviceNameArg4 = new Argument<FileInfo>(name: "prdFile", description: "Device to dump") { Arity = ArgumentArity.ExactlyOne };
        var outputDirOption2 = new Option<string?>(["-o", "--output"], "Output directory");
        
        exportDevice.AddArgument(deviceNameArg4);
        exportDevice.AddOption(outputDirOption2);
        
        exportDevice.SetHandler((deviceName, output) =>
        {
            var device = Device.Load(deviceName.FullName);
            
            var outDir = output ?? Path.GetFileNameWithoutExtension(deviceName.Name);
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
        }, deviceNameArg4, outputDirOption2);
        
        // serve
        
        var serve = new Command("serve", "Serve your local CDM and Playready Devices remotely");

        var configPathArg = new Argument<FileInfo>(name: "configPath", description: "Serve config file path") { Arity = ArgumentArity.ExactlyOne };
        var hostOption = new Option<string>(["-h", "--host"], description: "Host to serve from", getDefaultValue: () => "127.0.0.1");
        var portOption = new Option<string>(["-p", "--port"], description: "Port to serve from", getDefaultValue: () => "6798");
        
        serve.AddArgument(configPathArg);
        serve.AddOption(hostOption);
        serve.AddOption(portOption);
        
        serve.SetHandler((configPath, host, port) =>
        {
            IDeserializer deserializer = new StaticDeserializerBuilder(new YamlContext())
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();
            
            var yamlContent = File.ReadAllText(configPath.FullName);
            var configData = deserializer.Deserialize<YamlConfig.ConfigData>(yamlContent);
 
            var server = new Serve(host, Convert.ToInt32(port), configData);
            server.Run();
        }, configPathArg, hostOption, portOption);
        
        var rootCommand = new RootCommand($"csplayready (https://github.com/ready-dl/csplayready) version {Version} Copyright (c) 2025-{DateTime.Now.Year} DevLARLEY");
        
        rootCommand.AddCommand(createDevice);
        rootCommand.AddCommand(exportDevice);
        rootCommand.AddCommand(license);
        rootCommand.AddCommand(reprovisionDevice);
        rootCommand.AddCommand(test);
        rootCommand.AddCommand(serve);
        
        rootCommand.InvokeAsync(args).Wait();
        
        // TODO:
        //   + add Enums
        //   + cli function for testing remote cdm?
    }
}
