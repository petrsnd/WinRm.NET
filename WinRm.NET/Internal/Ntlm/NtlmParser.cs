namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Linq;
    using System.Text;
    using global::Kerberos.NET.Entities;

    internal sealed class NtlmParser
    {
        public static NtlmChallenge ParseChallenge(byte[] challengeBytes)
        {
            // Offset: 0
            // Signature (8 bytes)
            if (Encoding.ASCII.GetString(challengeBytes, 0, 8) != "NTLMSSP\0")
            {
                throw new ArgumentException("Missing signature: NTLMSSP", nameof(challengeBytes));
            }

            // Offset: 8
            // MessageType (4 bytes)
            if (BitConverter.ToInt32(challengeBytes, 8) != 2)
            {
                throw new ArgumentException("Invalid message type, expected 2 for challenge", nameof(challengeBytes));
            }

            NtlmChallenge challenge = new NtlmChallenge();

            // Offset: 12
            // TargetNameInfo (len 2 bytes, maxlen 2 bytes, offset 4 bytes)
            short targetNameLen = BitConverter.ToInt16(challengeBytes, 12);
            short targetNameLenMax = BitConverter.ToInt16(challengeBytes, 14);
            int targetNameOffset = BitConverter.ToInt32(challengeBytes, 16);
            if (targetNameLen > 0 && targetNameOffset > 0)
            {
                challenge.TargetName = Encoding.Unicode.GetString(challengeBytes, targetNameOffset, targetNameLen);
            }

            // Offset: 20
            // Flags (4 bytes)
            challenge.Flags = (NtlmNegotiateFlag)BitConverter.ToInt32(challengeBytes, 20);

            // Offset: 24
            // Challenge (8 bytes)
            challenge.ChallengeBytes = challengeBytes.Skip(24).Take(8).ToArray();

            // Offset: 32
            // Reserved (8 bytes)

            // Offset: 40
            // TargetInfo (len 2 bytes, maxlen 2 bytes, offset 4 bytes)
            short targetInfoLen = BitConverter.ToInt16(challengeBytes, 40);
            short targetInfoLenMax = BitConverter.ToInt16(challengeBytes, 42);
            int targetInfoOffset = BitConverter.ToInt32(challengeBytes, 44);
            if (targetInfoLen > 0 && targetInfoOffset > 0)
            {
                ParseTargetInfoAttributes(challenge, new ReadOnlySpan<byte>(challengeBytes, targetInfoOffset, targetInfoLen));
            }

            return challenge;
        }

        private static void ParseTargetInfoAttributes(NtlmChallenge challenge, ReadOnlySpan<byte> targetInfoBuffer)
        {
            var pairs = AvPairParser.Parse(targetInfoBuffer);
            foreach (var pair in pairs)
            {
                switch (pair.Type)
                {
                    case 0x0000: // EOF
                        return;
                    case 0x0001: // MsvAvNbComputerName
                        challenge.NetBiosComputerName = Encoding.Unicode.GetString(pair.Value);
                        break;
                    case 0x0002: // MsvAvNbDomainName
                        challenge.NetBiosDomainName = Encoding.Unicode.GetString(pair.Value);
                        break;
                    case 0x0003: // MsvAvDnsComputerName
                        challenge.DnsComputerName = Encoding.Unicode.GetString(pair.Value);
                        break;
                    case 0x0004: // MsvAvDnsDomainName
                        challenge.DnsDomainName = Encoding.Unicode.GetString(pair.Value);
                        break;
                    case 0x0005: // MsvAvDnsTreeName
                        challenge.DnsTreeName = Encoding.Unicode.GetString(pair.Value);
                        break;
                    case 0x0006: // MsvAvFlags
                        if (pair.Value.Length >= 4)
                        {
                            challenge.Flags = (NtlmNegotiateFlag)BitConverter.ToInt32(pair.Value, 0);
                        }

                        break;
                    case 0x0007: // MsvAvTimestamp
                        if (pair.Value.Length >= 8)
                        {
                            long timestamp = BitConverter.ToInt64(pair.Value, 0);
                            challenge.Timestamp = DateTime.FromFileTime(timestamp);
                        }

                        break;

                    case 0x0009: // MsvAvTargetName
                        challenge.TargetName = Encoding.Unicode.GetString(pair.Value);
                        break;

                    case 0x0008: // MsvAvSingleHost data
                    case 0x000A: // MsvAvChannelBindings
                        // Not processed
                        break;
                }
            }
        }
    }
}
