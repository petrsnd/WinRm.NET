namespace WinRm.NET.Internal.Kerberos
{
    using System.Globalization;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;
    using global::Kerberos.NET;
    using global::Kerberos.NET.Client;
    using global::Kerberos.NET.Configuration;
    using global::Kerberos.NET.Credentials;
    using global::Kerberos.NET.Entities;
    using Microsoft.Extensions.Logging;

    internal sealed class KerberosSecurityEnvelope : SecurityEnvelope
    {
        private readonly Credentials credentials;
        private readonly string realmName;
        private readonly string kdcAddress;
        private string? targetSpn;

        public KerberosSecurityEnvelope(ILogger? logger, Credentials credentials, string realm, string kdc, string? spn)
            : base(logger)
        {
            this.credentials = credentials;
            realmName = realm.ToUpper(CultureInfo.InvariantCulture);
            kdcAddress = kdc;
            targetSpn = spn;
        }

        public override string User => this.credentials.User;

        public override AuthType AuthType => AuthType.Kerberos;

        private ApplicationSessionContext? SessionContext { get; set; }

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

            var krb5Client = new KerberosClient(krb5Conf);
            krb5Client.PinKdc(realmName, kdcAddress);

            var creds = new KerberosPasswordCredential(credentials.User, credentials.Password);
            await krb5Client.Authenticate(creds);

            var apOptions = ApOptions.ChannelBindingSupported | ApOptions.MutualRequired;
            var targetHost = winRmProtocol.Endpoint.Host.ToLowerInvariant();
            if (targetSpn == null)
            {
                targetSpn = $"http/{targetHost}";
            }

            var rst = new RequestServiceTicket
            {
                ApOptions = apOptions,
                ServicePrincipalName = targetSpn,
                Realm = realmName,
                CacheTicket = true,
            };

            // This is the Krb5 context that will be used for this session
            SessionContext = await krb5Client.GetServiceTicket(rst);

            // Encode the AP_REQ in GSS-API for transmission via HTTP
            var requestHeaderBuffer = GssApiToken.Encode(new Oid(MechType.KerberosGssApi), SessionContext.ApReq);
            var gssKrb5ApReq = Convert.ToBase64String(requestHeaderBuffer.ToArray());

            using var httpClient = winRmProtocol.HttpClientFactory.CreateClient();
            httpClient.BaseAddress = WinRmProtocol.Endpoint;
            httpClient.Timeout = TimeSpan.FromSeconds(120);

            using var request = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Kerberos", gssKrb5ApReq);
            using var response = await httpClient.SendAsync(request);

            if (!response.Headers.TryGetValues("WWW-Authenticate", out var values))
            {
                throw new InvalidOperationException("[PROTOCOL_ERROR] WWW-Authenticate header not found in response.");
            }

            var gssKrb5ApRep = values.FirstOrDefault()?.Replace("Kerberos", string.Empty).Trim();
            if (string.IsNullOrEmpty(gssKrb5ApRep))
            {
                throw new InvalidOperationException("[PROTOCOL_ERROR] Got WWW-Authenticate, but it did not contain a Kerberos response.");
            }

            // Decode from GSS-API to get to the AP_REP
            var responseHeaderBuffer = Convert.FromBase64String(gssKrb5ApRep);
            var gssToken = GssApiToken.Decode(responseHeaderBuffer);
            var encKey = SessionContext.AuthenticateServiceResponse(gssToken.Token);

            int breakhere = 100;
        }

        protected override Task<string> DecodeResponse(HttpResponseMessage response)
        {
            throw new NotImplementedException();
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            throw new NotImplementedException();
        }

        protected override void SetHeaders(HttpRequestHeaders headers)
        {
            throw new NotImplementedException();
        }
    }
}
