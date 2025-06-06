namespace WinRm.NET.Internal.Kerberos
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;
    using global::Kerberos.NET.Client;
    using global::Kerberos.NET.Configuration;
    using global::Kerberos.NET.Credentials;
    using global::Kerberos.NET.Entities;
    using Microsoft.Extensions.Logging;

    internal sealed class KerberosSecurityEnvelope : SecurityEnvelope
    {
        private readonly Credentials credentials;
        private readonly HostInfo kdcInfo;
        private readonly string realmName;

        private bool _contextEstablished;

        public KerberosSecurityEnvelope(ILogger? logger, Credentials credentials, string realm, HostInfo kdcInfo)
            : base(logger)
        {
            this.credentials = credentials;
            realmName = realm;
            this.kdcInfo = kdcInfo;
        }

        public override string User => this.credentials.User;

        public override AuthType AuthType => AuthType.Kerberos;

        private KrbApReq? ServiceTicket { get; set; }

        // This is probably wrong...
        private string KrbToken { get; set; } = string.Empty;

        public async override Task Initialize(WinRmProtocol winRmProtocol)
        {
            await base.Initialize(winRmProtocol);

            var krb5Conf = new Krb5Config
            {
                Defaults =
                {
                    DefaultRealm = realmName,
                    DnsLookupKdc = false,
                    DefaultCCacheName = "MEMORY:",
                },
            };

            // need to figure out how to ask Kerberos for mutual auth and delegation in the AP_REQ
            // before we build the GSS-API token in the authorization header.

            var client = new KerberosClient(krb5Conf);
            client.PinKdc(kdcInfo.Name, kdcInfo.Address);

            var creds = new KerberosPasswordCredential(credentials.User, credentials.Password);
            client.Authenticate(creds).Wait();

            var apOptions = ApOptions.ChannelBindingSupported | ApOptions.MutualRequired;
            var targetHost = winRmProtocol.Endpoint.Host.ToLowerInvariant();
            ServiceTicket = client.GetServiceTicket($"http/{targetHost}", apOptions).GetAwaiter().GetResult();
            var buffer = GssApiToken.Encode(new Oid(MechType.KerberosGssApi), ServiceTicket);
            KrbToken = Convert.ToBase64String(buffer.ToArray());
        }

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

        protected override void SetHeaders(HttpRequestHeaders headers)
        {
            headers.Authorization = new AuthenticationHeaderValue("Kerberos", KrbToken);
        }
    }
}