namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using global::Kerberos.NET.Entities;

    internal sealed class NtlmChallenge
    {
        public string TargetName { get; set; } = string.Empty;

        public byte[] ChallengeBytes { get; set; } = Array.Empty<byte>();

        public NtlmNegotiateFlag Flags { get; set; }

        public string NetBiosDomainName { get; set; } = string.Empty;

        public string NetBiosComputerName { get; set; } = string.Empty;

        public string DnsDomainName { get; set; } = string.Empty;

        public string DnsComputerName { get; set; } = string.Empty;

        public string DnsTreeName { get; set; } = string.Empty;

        public DateTime Timestamp { get; set; } = DateTime.MinValue;
    }
}
