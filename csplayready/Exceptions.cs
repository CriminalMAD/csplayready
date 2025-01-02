namespace csplayready;


public class CsPlayreadyException : Exception
{
    public CsPlayreadyException(string message) : base(message) { }
    public CsPlayreadyException(string message, Exception innerException) : base(message, innerException) { }
}

public class InvalidCertificate : CsPlayreadyException
{
    public InvalidCertificate(string message) : base(message) { }
    public InvalidCertificate(string message, Exception innerException) : base(message, innerException) { }
}

public class InvalidCertificateChain : CsPlayreadyException
{
    public InvalidCertificateChain(string message) : base(message) { }
    public InvalidCertificateChain(string message, Exception innerException) : base(message, innerException) { }
}

public class TooManySessions : CsPlayreadyException
{
    public TooManySessions(string message) : base(message) { }
    public TooManySessions(string message, Exception innerException) : base(message, innerException) { }
}

public class InvalidSession : CsPlayreadyException
{
    public InvalidSession(string message) : base(message) { }
    public InvalidSession(string message, Exception innerException) : base(message, innerException) { }
}

public class InvalidLicense : CsPlayreadyException
{
    public InvalidLicense(string message) : base(message) { }
    public InvalidLicense(string message, Exception innerException) : base(message, innerException) { }
}
