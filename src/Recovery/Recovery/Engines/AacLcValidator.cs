using System;
using System.Collections.Generic;

namespace UsbRecovery
{
    // Bounded AAC-LC raw_data_block syntax walk, without PCM synthesis. AAC has
    // no payload checksum: successful parsing never authenticates old audio.
    // Syntax cross-check: FFmpeg n8.0 aacdec.c and aacdec_proc_template.c,
    // ISO/IEC 14496-3 individual_channel_stream / spectral_data / raw_data_block.
    public static class AacLcValidator
    {
        public const int MaximumSampleBytes = 16384;
        sealed class Invalid : Exception { public string Code; public Invalid(string code) { Code = code; } }
        sealed class Bits
        {
            public byte[] Data; public int At;
            public int Remaining { get { return Data.Length * 8 - At; } }
            public int Get(int count)
            {
                if (count < 0 || count > 24 || count > Remaining) throw new Invalid("aac_syntax_truncated");
                int value = 0; for (int i = 0; i < count; i++, At++) value = (value << 1) | ((Data[At / 8] >> (7 - At % 8)) & 1); return value;
            }
            public void Skip(int count) { if (count < 0 || count > Remaining) throw new Invalid("aac_syntax_truncated"); At += count; }
            public void Align() { int count = (8 - At % 8) % 8; if (Get(count) != 0) throw new Invalid("aac_alignment_nonzero"); }
        }
        sealed class Node { public int Zero = -1, One = -1, Value = -1; }
        sealed class Huffman
        {
            readonly List<Node> tree = new List<Node> { new Node() };
            public Huffman(int[] codes, int[] lengths)
            {
                if (codes.Length != lengths.Length) throw new InvalidOperationException("AAC_TABLE_LENGTH");
                for (int symbol = 0; symbol < codes.Length; symbol++) {
                    int at = 0;
                    for (int bit = lengths[symbol] - 1; bit >= 0; bit--) {
                        if (tree[at].Value >= 0) throw new InvalidOperationException("AAC_TABLE_PREFIX");
                        bool one = ((codes[symbol] >> bit) & 1) != 0; int next = one ? tree[at].One : tree[at].Zero;
                        if (next < 0) { next = tree.Count; tree.Add(new Node()); if (one) tree[at].One = next; else tree[at].Zero = next; }
                        at = next;
                    }
                    if (tree[at].Value >= 0 || tree[at].Zero >= 0 || tree[at].One >= 0) throw new InvalidOperationException("AAC_TABLE_DUPLICATE");
                    tree[at].Value = symbol;
                }
            }
            public int Read(Bits bits)
            {
                int at = 0;
                for (int i = 0; i < 20; i++) {
                    at = bits.Get(1) == 0 ? tree[at].Zero : tree[at].One;
                    if (at < 0) throw new Invalid("aac_huffman_code_invalid");
                    if (tree[at].Value >= 0) return tree[at].Value;
                }
                throw new Invalid("aac_huffman_length_invalid");
            }
        }
        sealed class Ics { public bool Short; public int MaximumBand; public int[] Offsets; public List<int> Groups = new List<int>(); }
        static readonly Huffman Scale = new Huffman(AacSyntaxTables.ScaleCodes, AacSyntaxTables.ScaleBits);
        static readonly Huffman[] Books = MakeBooks();
        static Huffman[] MakeBooks() { var books = new Huffman[11]; for (int i = 0; i < books.Length; i++) books[i] = new Huffman(AacSyntaxTables.Codes[i], AacSyntaxTables.Bits[i]); return books; }

        public static bool IsPossibleStart(byte[] bytes, int at)
        {
            if (bytes == null || at < 0 || at > bytes.Length - 2) return false;
            int kind = bytes[at] >> 5;
            if (kind == 0 || kind == 1 || kind == 4) return true;
            if (kind != 6) return false;
            int count = (bytes[at] >> 1) & 15;
            if (count == 0 || count == 15) return true;
            int extension = ((bytes[at] & 1) << 3) | (bytes[at + 1] >> 5);
            return extension == 0 || extension == 1 || extension == 11;
        }

        public static bool TryValidate(byte[] sample, int channels, int frequencyIndex, out string code)
        {
            code = null;
            if (sample == null || sample.Length < 2 || sample.Length > MaximumSampleBytes || channels < 1 || channels > 2 || frequencyIndex < 0 || frequencyIndex > 12) { code = "aac_syntax_configuration_or_size"; return false; }
            try {
                var bits = new Bits { Data = sample }; bool audio = false;
                for (int element = 0; element < 32; element++) {
                    int kind = bits.Get(3);
                    if (kind == 7) {
                        if (!audio) throw new Invalid("aac_channel_element_missing");
                        bits.Align(); if (bits.Remaining != 0) throw new Invalid("aac_trailing_bytes"); return true;
                    }
                    if (kind == 6) {
                        int count = bits.Get(4); if (count == 15) count = 14 + bits.Get(8);
                        if (count > 0) Fill(bits,count);
                        continue;
                    }
                    if (kind == 4) {
                        bits.Get(4); bool align = bits.Get(1) != 0; int count = bits.Get(8); if (count == 255) count += bits.Get(8);
                        if (align) bits.Align(); bits.Skip(count * 8); continue;
                    }
                    if (audio || kind != (channels == 1 ? 0 : 1)) throw new Invalid("aac_channel_element_unsupported");
                    audio = true; bits.Get(4);
                    if (kind == 0) Channel(bits, null, frequencyIndex);
                    else {
                        bool common = bits.Get(1) != 0; Ics shared = common ? Info(bits, frequencyIndex) : null;
                        if (common) { int mask = bits.Get(2); if (mask == 3) throw new Invalid("aac_ms_mask_reserved"); if (mask == 1) bits.Skip(shared.Groups.Count * shared.MaximumBand); }
                        Channel(bits, shared, frequencyIndex); Channel(bits, shared, frequencyIndex);
                    }
                }
                throw new Invalid("aac_element_limit");
            } catch (Invalid error) { code = error.Code; return false; }
        }
        static Ics Info(Bits bits, int frequency)
        {
            if (bits.Get(1) != 0) throw new Invalid("aac_ics_reserved_bit");
            int sequence = bits.Get(2); bits.Get(1); var ics = new Ics { Short = sequence == 2 };
            ics.Offsets = ics.Short ? AacSyntaxTables.ShortBands[frequency] : AacSyntaxTables.LongBands[frequency];
            ics.MaximumBand = bits.Get(ics.Short ? 4 : 6); ics.Groups.Add(1);
            if (ics.Short) { for (int i = 0; i < 7; i++) if (bits.Get(1) != 0) ics.Groups[ics.Groups.Count - 1]++; else ics.Groups.Add(1); }
            else if (bits.Get(1) != 0) throw new Invalid("aac_lc_prediction_forbidden");
            if (ics.MaximumBand >= ics.Offsets.Length) throw new Invalid("aac_scalefactor_band_bounds"); return ics;
        }
        static void Fill(Bits bits,int bytes)
        {
            int end=bits.At+bytes*8;if(end-bits.At>bits.Remaining)throw new Invalid("aac_syntax_truncated");
            while(bits.At<end){
                int beginning=bits.At,type=bits.Get(4);
                if(type==0||type==1){bits.Skip(end-bits.At);return;}
                if(type!=11)throw new Invalid("aac_fill_extension_unsupported");
                if(bits.Get(1)!=0){bits.Get(4);if(bits.Get(4)!=0)throw new Invalid("aac_drc_reserved_bits");}
                if(bits.Get(1)!=0){int groups=0;bool more;do{bits.Get(7);more=bits.Get(1)!=0;if(++groups>7)throw new Invalid("aac_drc_exclusion_limit");}while(more);}
                int bands=1;if(bits.Get(1)!=0){bands+=bits.Get(4);bits.Get(4);int previous=-1;for(int i=0;i<bands;i++){int top=bits.Get(8);if(top<=previous)throw new Invalid("aac_drc_band_bounds");previous=top;}}
                if(bits.Get(1)!=0){bits.Get(7);if(bits.Get(1)!=0)throw new Invalid("aac_drc_reserved_bits");}
                bits.Skip(bands*8);if(bits.At>end||(bits.At-beginning)%8!=0)throw new Invalid("aac_drc_payload_bounds");
            }
        }
        static void Channel(Bits bits, Ics shared, int frequency)
        {
            int gain = bits.Get(8); Ics ics = shared ?? Info(bits, frequency); var bands = new List<int>();
            int sectionBits = ics.Short ? 3 : 5, escape = (1 << sectionBits) - 1;
            foreach (int group in ics.Groups) {
                int band = 0;
                while (band < ics.MaximumBand) {
                    int type = bits.Get(4); if (type == 12) throw new Invalid("aac_reserved_codebook");
                    int length = 0, increment;
                    do { increment = bits.Get(sectionBits); length += increment; if (length > ics.MaximumBand - band) throw new Invalid("aac_section_bounds"); } while (increment == escape);
                    if (length == 0) throw new Invalid("aac_empty_section");
                    for (int i = 0; i < length; i++) bands.Add(type); band += length;
                }
            }
            bool firstNoise = true;
            foreach (int type in bands) {
                if (type == 0) continue;
                if (type == 13 && firstNoise) { bits.Get(9); firstNoise = false; }
                else { int delta = Scale.Read(bits) - 60; if (type < 12) { gain += delta; if (gain < 0 || gain > 255) throw new Invalid("aac_scalefactor_gain_bounds"); } }
            }
            if (bits.Get(1) != 0) {
                if (ics.Short) throw new Invalid("aac_short_pulse_forbidden"); int count = bits.Get(2) + 1, band = bits.Get(6);
                if (band >= ics.Offsets.Length - 1) throw new Invalid("aac_pulse_band_bounds"); int position = ics.Offsets[band];
                for (int i = 0; i < count; i++) { position += bits.Get(5); bits.Get(4); if (position >= 1024) throw new Invalid("aac_pulse_position_bounds"); }
            }
            if (bits.Get(1) != 0) Tns(bits, ics);
            if (bits.Get(1) != 0) throw new Invalid("aac_gain_control_unsupported");
            int index = 0;
            foreach (int group in ics.Groups) for (int band = 0; band < ics.MaximumBand; band++, index++) {
                int type = bands[index]; if (type == 0 || type >= 13) continue;
                int dimension = type <= 4 ? 4 : 2, values = (ics.Offsets[band + 1] - ics.Offsets[band]) * group;
                if (values % dimension != 0) throw new Invalid("aac_spectral_band_alignment");
                for (int i = 0; i < values; i += dimension) Spectral(bits, type);
            }
        }
        static void Tns(Bits bits, Ics ics)
        {
            for (int window = 0; window < (ics.Short ? 8 : 1); window++) {
                int filters = bits.Get(ics.Short ? 1 : 2); if (filters == 0) continue; int resolution = bits.Get(1);
                for (int filter = 0; filter < filters; filter++) {
                    bits.Get(ics.Short ? 4 : 6); int order = bits.Get(ics.Short ? 3 : 5);
                    if (order > (ics.Short ? 7 : 12)) throw new Invalid("aac_tns_order_bounds");
                    if (order > 0) { bits.Get(1); int compressed = bits.Get(1); bits.Skip(order * (resolution + 3 - compressed)); }
                }
            }
        }
        static void Spectral(Bits bits, int type)
        {
            int symbol = Books[type - 1].Read(bits);
            if (type <= 2 || type == 5 || type == 6) return;
            int dimension = type <= 4 ? 4 : 2, basis = type <= 4 ? 3 : type <= 8 ? 8 : type <= 10 ? 13 : 17;
            int escapes = 0;
            for (int i = 0; i < dimension; i++) { int value = symbol % basis; symbol /= basis; if (value != 0) bits.Get(1); if (type == 11 && value == 16) escapes++; }
            for (int i = 0; i < escapes; i++) { int ones = 0; while (bits.Get(1) != 0) if (++ones > 8) throw new Invalid("aac_escape_overflow"); bits.Skip(ones + 4); }
        }
    }
}
