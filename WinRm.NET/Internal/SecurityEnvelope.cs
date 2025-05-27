namespace WinRm.NET.Internal
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;

    internal abstract class SecurityEnvelope : ISecurityEnvelope
    {
        public SecurityEnvelope(WinRmProtocol winRmProtocol)
        {
            this.WinRmProtocol = winRmProtocol;
        }

        protected WinRmProtocol WinRmProtocol { get; }

        /// <summary>
        /// Send the SOAP message and handle errors. If successful,
        /// return the response as an XmlDocument. Derived classes are responsible
        /// for setting up the authorization headers and encrypting/decrypting the
        /// payloads.
        /// </summary>
        /// <param name="soapDocument">The SOAP request document</param>
        /// <param name="credentials">User's credentials for the request</param>
        /// <returns>XmlDocument response</returns>
        public async Task<XmlDocument> SendMessage(XmlDocument soapDocument, Credentials credentials)
        {
            using var client = this.WinRmProtocol.HttpClientFactory.CreateClient();
            client.BaseAddress = this.WinRmProtocol.Endpoint;
            client.Timeout = TimeSpan.FromSeconds(120); // Hard-coded 2 minute timeout in case no one is home

            using var request = new HttpRequestMessage(HttpMethod.Post, this.WinRmProtocol.Endpoint);
            SetHeaders(request.Headers, credentials);
            SetContent(request, soapDocument);
            request.Headers.Add("User-Agent", "Microsoft WinRM Client");
            request.Headers.Add("Connection", "Keep-Alive");
            request.Headers.Add("SOAPAction", string.Empty);
            using var response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                // TODO: pywinrm checks for all these soap faults, which we should do too
                // if there are stupid problems we should maybe retry here as well. I know we have
                // seen some stupid things like "local error occurred" which we can probably retry
                // successfully.

                //    fault = root.find("soapenv:Body/soapenv:Fault", xmlns)
                //if fault is None:
                //    raise

                //wsmanfault_code_raw = fault.find("soapenv:Detail/wsmanfault:WSManFault[@Code]", xmlns)
                //wsmanfault_code: int | None = None
                //if wsmanfault_code_raw is not None:
                //    wsmanfault_code = int(wsmanfault_code_raw.attrib["Code"])

                //    # convert receive timeout code to WinRMOperationTimeoutError
                //    if wsmanfault_code == 2150858793:
                //        # TODO: this fault code is specific to the Receive operation; convert all op timeouts?
                //        raise WinRMOperationTimeoutError()

                //fault_code_raw = fault.find("soapenv:Code/soapenv:Value", xmlns)
                //fault_code: str | None = None
                //if fault_code_raw is not None and fault_code_raw.text:
                //    fault_code = fault_code_raw.text

                //fault_subcode_raw = fault.find("soapenv:Code/soapenv:Subcode/soapenv:Value", xmlns)
                //fault_subcode: str | None = None
                //if fault_subcode_raw is not None and fault_subcode_raw.text:
                //    fault_subcode = fault_subcode_raw.text

                //error_message_node = fault.find("soapenv:Reason/soapenv:Text", xmlns)
                //reason: str | None = None
                //if error_message_node is not None:
                //    reason = error_message_node.text

                //wmi_error_code_raw = fault.find("soapenv:Detail/wmierror:MSFT_WmiError/wmierror:error_Code", xmlns)
                //wmi_error_code: int | None = None
                //if wmi_error_code_raw is not None and wmi_error_code_raw.text:
                //    wmi_error_code = int(wmi_error_code_raw.text)

                var responseContent = await DecodeResponse(response);
                var xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(responseContent);
                return xmlDocument;
            }
            else
            {
                var responseData = await response.Content.ReadAsStringAsync();
                // TODO: Define specific exceptions that we will throw from WinRm.NET
                throw new HttpRequestException($"Error: {response.StatusCode}, {response.ReasonPhrase} SOAP Response: {responseData}");
            }
        }

        protected abstract void SetHeaders(HttpRequestHeaders headers, Credentials credentials);

        protected abstract void SetContent(HttpRequestMessage request, XmlDocument soapDocument);

        protected abstract Task<string> DecodeResponse(HttpResponseMessage response);
    }
}
