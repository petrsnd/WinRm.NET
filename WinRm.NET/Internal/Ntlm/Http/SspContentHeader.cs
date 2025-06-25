namespace WinRm.NET.Internal.Ntlm.Http
{
    using System.Net.Http.Headers;

    internal class SspContentHeader : MediaTypeHeaderValue
    {
        private readonly string contentType;

        public SspContentHeader(string contentType)
            : base("multipart/encrypted")
        {
            this.contentType = contentType;
        }

        public override string ToString()
        {
            return $"multipart/encrypted;protocol=\"{this.contentType}\";boundary=\"Encrypted Boundary\"";
        }
    }
}