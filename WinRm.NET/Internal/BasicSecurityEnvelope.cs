namespace WinRm.NET.Internal
{
    using System;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;

    /// <summary>
    /// Basic security is not secure. Sends unencrypted payload with Basic
    /// auth header. This is only for testing and development purposes.
    /// </summary>
    /// <param name="winRmProtocol">Parent winrm protocol</param>
    internal sealed class BasicSecurityEnvelope(WinRmProtocol winRmProtocol)
        : SecurityEnvelope(winRmProtocol)
    {
        protected async override Task<string> DecodeResponse(HttpResponseMessage response)
        {
            return await response.Content.ReadAsStringAsync();
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            request.Content = new StringContent(soapDocument.OuterXml, Encoding.UTF8, "application/soap+xml");
        }

        protected override void SetHeaders(HttpRequestHeaders headers, Credentials credentials)
        {
            var authenticationString = $"{credentials.User}:{credentials.Password ?? string.Empty}";
            var base64EncodedAuthenticationString = Convert.ToBase64String(System.Text.UTF8Encoding.UTF8.GetBytes(authenticationString));
            headers.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);
        }
    }
}