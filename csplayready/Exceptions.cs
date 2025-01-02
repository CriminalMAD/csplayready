namespace csplayready;


public class CsPlayreadyException : Exception
{
    protected CsPlayreadyException(string message) : base(message) { }
    protected CsPlayreadyException(string message, Exception innerException) : base(message, innerException) { }
}

public class InvalidCertificate(string message) : CsPlayreadyException(message);
public class InvalidCertificateChain(string message, Exception innerException) : CsPlayreadyException(message, innerException);
public class TooManySessions(string message) : CsPlayreadyException(message);
public class InvalidSession(string message) : CsPlayreadyException(message);
public class InvalidLicense(string message) : CsPlayreadyException(message);
public class OutdatedDevice(string message) : CsPlayreadyException(message);
