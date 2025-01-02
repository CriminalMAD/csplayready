using csplayready.crypto;
using csplayready.license;

namespace csplayready.system;

public class Session(int number)
{
    public readonly int Number = number;
    public readonly int Id = new Random().Next(1, int.MaxValue);
    public readonly XmlKey XmlKey = new XmlKey();
    public EccKey? SigningKey = null;
    public EccKey? EncryptionKey = null;
    public List<Key> Keys = [];
}
