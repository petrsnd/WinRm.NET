namespace WinRm.NET.Internal
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;

    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;

    using Kerberos.NET;
    using Kerberos.NET.Client;
    using Kerberos.NET.Configuration;
    using Kerberos.NET.Credentials;
    using Kerberos.NET.Entities;

    internal sealed class KerberosSecurityEnvelope(WinRmProtocol winRmProtocol) : SecurityEnvelope(winRmProtocol)
    {
        private bool _contextEstablished;

        private KrbApReq? ServiceTicket { get; set; }

        protected override Task<string> DecodeResponse(HttpResponseMessage response)
        {
            throw new NotImplementedException();
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            if (ServiceTicket == null)
            {
                throw new InvalidOperationException("SetHeaders must be called before SetContent");
            }

            if (!_contextEstablished)
            {
                request.Content = new StringContent(soapDocument.OuterXml, Encoding.UTF8, "application/soap+xml");
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        protected override void SetHeaders(HttpRequestHeaders headers, Credentials credentials)
        {
            var krb5Conf = new Krb5Config
            {
                Defaults =
                {
                    DefaultRealm = "DAN.HOME",
                    DnsLookupKdc = false,
                    DefaultCCacheName = "MEMORY:",
                },
            };

            // need to figure out how to ask Kerberos for mutual auth and delegation in the AP_REQ
            // before we build the GSS-API token in the authorization header.

            var client = new KerberosClient(krb5Conf);
            client.PinKdc("DAN.HOME", "192.168.117.5");

            var creds = new KerberosPasswordCredential(credentials.User, credentials.Password);
            client.Authenticate(creds).Wait();

            var apOptions = ApOptions.ChannelBindingSupported | ApOptions.MutualRequired;
            ServiceTicket = client.GetServiceTicket("http/rdp1.dan.home", apOptions).GetAwaiter().GetResult();
            var buffer = GssApiToken.Encode(new Oid(MechType.KerberosGssApi), ServiceTicket);
            var base64Buffer = Convert.ToBase64String(buffer.ToArray());

            headers.Authorization = new AuthenticationHeaderValue("Kerberos", base64Buffer);
        }
    }
}