namespace WinRm.NET.Internal.Ntlm
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using System.Xml;
    using Microsoft.Extensions.Logging;

    internal sealed class NtlmSecurityEnvelope : SecurityEnvelope
    {
        private Credentials credentials;

        public NtlmSecurityEnvelope(ILogger? logger, Credentials credentials)
            : base(logger)
        {
            this.credentials = credentials;
        }

        public override string User => this.credentials.User;

        public override AuthType AuthType => AuthType.Ntlm;

        public override async Task Initialize(WinRmProtocol winRmProtocol)
        {
            await base.Initialize(winRmProtocol);

            using var client = winRmProtocol.HttpClientFactory.CreateClient();
            client.BaseAddress = WinRmProtocol.Endpoint;
            client.Timeout = TimeSpan.FromSeconds(120);

            // Create NTLMSSP negotiate header
            var negotiate = new NegotiateMessageBuilder();
            var bytes = negotiate.Build();
            Log.Dbg(Logger, $"Negotiate: {bytes.ToHexString()}");
            var token = bytes.ToBase64();

            var request = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", token);

            var response = await client.SendAsync(request);
            // Deal with the challenge response
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("Received 401 Unauthorized, processing NTLM challenge.");
                if (!response.Headers.TryGetValues("WWW-Authenticate", out var values))
                {
                    throw new InvalidOperationException("WWW-Authenticate header not found in response.");
                }

                var challengeMessage = values.First().Replace("Negotiate ", string.Empty).Trim();
                var challengeBytes = Convert.FromBase64String(challengeMessage);
                var challenge = NtlmParser.ParseChallenge(bytes);

                Logger.Dbg($"Challenge: {challenge.ChallengeBytes.ToHexString()}");
            }
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