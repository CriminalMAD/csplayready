using csplayready.crypto;
using csplayready.license;

namespace csplayready.system;

public class Session
{
    public readonly byte[] Id = Crypto.GetRandomBytes(16);
    public readonly XmlKey XmlKey = new();
    public EccKey? SigningKey = null;
    public EccKey? EncryptionKey = null;
    public readonly List<Key> Keys = [];
}
