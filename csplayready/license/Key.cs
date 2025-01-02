namespace csplayready.license;

public class Key(byte[] keyId, Key.KeyTypes keyType, Key.CipherTypes cipherType, byte[] rawKey)
{
    public enum KeyTypes : ushort
    {
        Invalid = 0x0000,
        Aes128Ctr = 0x0001,
        Rc4Cipher = 0x0002,
        Aes128Ecb = 0x0003,
        Cocktail = 0x0004,
        Aes128Cbc = 0x0005,
        KeyExchange = 0x0006
    }

    public enum CipherTypes : ushort
    {
        Invalid = 0x0000,
        Rsa1024 = 0x0001,
        ChainedLicense = 0x0002,
        Ecc256 = 0x0003,
        Ecc256WithKz = 0x0004,
        TeeTransient = 0x0005,
        Ecc256ViaSymmetric = 0x0006
    }

    public readonly byte[] KeyId = keyId;
    public readonly KeyTypes KeyType = keyType;
    public readonly CipherTypes CipherType = cipherType;
    public readonly byte[] RawKey = rawKey;
}