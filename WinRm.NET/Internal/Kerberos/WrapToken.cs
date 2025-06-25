namespace WinRm.NET.Internal.Kerberos
{
    using System;
    using System.Buffers.Binary;
    using System.Numerics;
    using System.Text;
    using System.Threading.Tasks;
    using WinRm.NET.Internal.Ntlm;

    internal enum TokenId
    {
        KrbTokenCfxMic = 0x0404,
        KrbTokenCfxWrap = 0x0504,
    }

    internal class WrapToken
    {
        public TokenId TokenId { get; set; }

        public ushort Ec { get; set; }

        public ushort Rrc { get; set; }

        public ulong SequenceNumber { get; set; }

        public bool SentByAcceptor { get; set; }

        public bool Sealed { get; set; } = true;

        public bool AcceptorSubKey { get; set; } = true;

        public ReadOnlyMemory<byte> GetBytes()
        {
            var bytes = new Memory<byte>(new byte[16]);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.Span[0..2], (ushort)this.TokenId);
            var flags = (byte)((this.SentByAcceptor ? 0x0001 : 0)
                | (this.Sealed ? 0x0002 : 0)
                | (this.AcceptorSubKey ? 0x0004 : 0));
            bytes.Span[2] = flags;
            bytes.Span[3] = 0xFF; // Filler
            BinaryPrimitives.WriteUInt16BigEndian(bytes.Span[4..], Ec); // EC - Extra count
            BinaryPrimitives.WriteUInt16BigEndian(bytes.Span[6..], Rrc); // RCC - Right rotation count
            BinaryPrimitives.WriteUInt64BigEndian(bytes.Span[8..], SequenceNumber); // SEQ_NUM
            return bytes;
        }
    }
}
