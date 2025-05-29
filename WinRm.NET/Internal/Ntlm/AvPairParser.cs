namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal sealed class AvPairParser
    {
        public static List<AvPair> Parse(ReadOnlySpan<byte> avList)
        {
            List<AvPair> pairs = new List<AvPair>();
            int offset = 0;
            while (offset < avList.Length)
            {
                if (avList.Length - offset < 4)
                {
                    throw new ArgumentException("Invalid AV pair length, expected at least 4 bytes for type and length", nameof(avList));
                }

                ushort type = BitConverter.ToUInt16(avList.Slice(offset, 2));
                ushort length = BitConverter.ToUInt16(avList.Slice(offset + 2, 2));
                offset += 4;

                if (avList.Length - offset < length)
                {
                    throw new ArgumentException("Invalid AV pair length, not enough data for value", nameof(avList));
                }

                byte[] value = avList.Slice(offset, length).ToArray();
                pairs.Add(new AvPair(type, value));
                offset += length;
            }

            return pairs;
        }
    }

    internal sealed class AvPair
    {
        [SetsRequiredMembers]
        public AvPair(ushort type, byte[] value)
        {
            this.Type = type;
            this.Value = value;
        }

        required public ushort Type { get; init; }

        required public byte[] Value { get; init; }

        public string TypeName => Type switch {
            0x0000 => "MsvAvEOL",
            0x0001 => "MsvAvNbComputerName",
            0x0002 => "MsvAvNbDomainName",
            0x0003 => "MsvAvDnsComputerName",
            0x0004 => "MsvAvDnsDomainName",
            0x0005 => "MsvAvDnsTreeName",
            0x0006 => "MsvAvFlags",
            0x0007 => "MsvAvTimestamp",
            0x0008 => "MsvAvSingleHost",
            0x0009 => "MsvAvTargetName",
            0x000A => "MsvAvChannelBindings",
            _ => $"Unknown ({Type})" };

        public string StringValue()
        {
            if (Type == 0x0000)
            {
                return "EOL";
            }
            else if (Type == 0x0009 || (Type >= 0x0001 && Type <= 0x0005))
            {
                return Encoding.Unicode.GetString(Value);
            }
            else if (Type == 0x0006)
            {
                var flags = BitConverter.ToInt32(Value);
                var sb = new StringBuilder("Flags:");
                if ((flags & 0x00000001) != 0)
                {
                    sb.Append(" (constrained)");
                }

                if ((flags & 0x00000002) != 0)
                {
                    sb.Append(" (message integrity included)");
                }

                if ((flags & 0x00000004) != 0)
                {
                    sb.Append(" (untrusted target SPN)");
                }

                return sb.ToString();
            }
            else if (Type == 0x0007)
            {
                var fileTime = BitConverter.ToInt64(Value);
                return DateTime.FromFileTimeUtc(fileTime).ToString("o"); // ISO 8601 format
            }
            else if (Type == 0x0008)
            {
                return "Single Host Data (not implemented) see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f221c061-cc40-4471-95da-d2ff71c85c5b";
            }
            else if (Type == 0x000A)
            {
                return Encoding.ASCII.GetString(Value);
            }

            return $"Unknown Type (0x{BitConverter.GetBytes(Type).ToHexString()})";
        }
    }
}
