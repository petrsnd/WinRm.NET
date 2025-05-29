namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using global::Kerberos.NET.Entities;

    internal sealed class NegotiateMessageBuilder
    {
        private NtlmNegotiateFlag flags = NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM_V1
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_LM_KEY
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN
            | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
            | NtlmNegotiateFlag.NTLM_NEGOTIATE_OEM
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE;

        public NegotiateMessageBuilder()
        {
        }

        public NegotiateMessageBuilder SetFlag(NtlmNegotiateFlag flag)
        {
            flags |= flag;
            return this;
        }

        public NegotiateMessageBuilder ClearFlag(NtlmNegotiateFlag flag)
        {
            flags &= ~flag;
            return this;
        }

        public byte[] Build()
        {
            List<byte> messageBytes = new List<byte>();
            messageBytes.AddRange(Encoding.ASCII.GetBytes("NTLMSSP\0")); // Signature
            messageBytes.AddRange(BitConverter.GetBytes((int)1)); // Message type (Negotiate)
            messageBytes.AddRange(BitConverter.GetBytes((int)flags)); // Flags
            messageBytes.AddRange(new byte[8]); // OEM DOMAIN - not set, so 8 zero bytes
            messageBytes.AddRange(new byte[8]); // OEM WORKSTATION - not set, so 8 zero bytes
            // Better to pretend to be windows even though the version is allegedly not used
            messageBytes.Add((byte)10); // Major version
            messageBytes.Add((byte)0); // Minor version
            messageBytes.AddRange(BitConverter.GetBytes((short)26100)); // build 26100
            messageBytes.AddRange(new byte[3]); // Reserved
            messageBytes.Add((byte)15); // NTLM revision (15 for NTLMv2)
            return messageBytes.ToArray();
        }
    }
}
