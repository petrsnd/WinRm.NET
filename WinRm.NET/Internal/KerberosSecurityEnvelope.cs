namespace WinRm.NET.Internal
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using System.Xml;

    internal sealed class KerberosSecurityEnvelope(WinRmProtocol winRmProtocol) : SecurityEnvelope(winRmProtocol)
    {
        protected override Task<string> DecodeResponse(HttpResponseMessage response)
        {
            throw new NotImplementedException();
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            throw new NotImplementedException();
        }

        protected override void SetHeaders(HttpRequestHeaders headers, Credentials credentials)
        {
            throw new NotImplementedException();
        }
    }
}