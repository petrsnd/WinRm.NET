namespace WinRm.NET.Internal
{
    using System.Xml;

    internal interface ISecurityEnvelope : IAsyncDisposable
    {
        AuthType AuthType { get; }

        string User { get; }

        Task Initialize(WinRmProtocol winRmProtocol);

        Task<XmlDocument> SendMessage(XmlDocument soapDocument);
    }
}