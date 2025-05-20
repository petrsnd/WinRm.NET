namespace WinRm.NET.Internal
{
    using System.Xml;

    internal interface ISecurityEnvelope
    {
        Task<XmlDocument> SendMessage(XmlDocument soapDocument, Credentials credentials);
    }
}