using System;
using System.Security.Cryptography;

namespace UsbRecovery
{
    internal static class BitcoinPublicAddress
    {
        const string Base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        const string Bech32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        static readonly uint[] Generators = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

        public static bool IsValid(string value, SHA256 hash)
        {
            if (value.StartsWith("bc1", StringComparison.OrdinalIgnoreCase)) return ValidWitness(value);
            if (value.Length < 26 || value.Length > 35 || (value[0] != '1' && value[0] != '3')) return false;

            // Mainnet legacy addresses encode a version, 20-byte hash and four checksum bytes.
            var decoded = new byte[25];
            foreach (char c in value)
            {
                int carry = Base58.IndexOf(c);
                if (carry < 0) return false;
                for (int i = decoded.Length - 1; i >= 0; i--)
                {
                    carry += 58 * decoded[i];
                    decoded[i] = (byte)carry;
                    carry >>= 8;
                }
                if (carry != 0) return false;
            }
            int ones = 0, zeros = 0;
            while (ones < value.Length && value[ones] == '1') ones++;
            while (zeros < decoded.Length && decoded[zeros] == 0) zeros++;
            if (ones != zeros || (decoded[0] != 0 && decoded[0] != 5)) return false;
            byte[] checksum = hash.ComputeHash(hash.ComputeHash(decoded, 0, 21));
            for (int i = 0; i < 4; i++) if (checksum[i] != decoded[21 + i]) return false;
            return true;
        }

        static uint Step(uint checksum, int value)
        {
            uint high = checksum >> 25;
            uint next = ((checksum & 0x1ffffff) << 5) ^ (uint)value;
            for (int i = 0; i < Generators.Length; i++)
                if ((high & (1u << i)) != 0) next ^= Generators[i];
            return next;
        }

        static bool ValidWitness(string value)
        {
            if (value.Length < 14 || value.Length > 90) return false;
            string lower = value.ToLowerInvariant();
            if (value != lower && value != value.ToUpperInvariant()) return false;
            int version = Bech32.IndexOf(lower[3]);
            if (version < 0 || version > 16) return false;
            uint checksum = 1;
            // BIP173 human-readable prefix expansion for "bc".
            foreach (int part in new[] { 3, 3, 0, 2, 3 }) checksum = Step(checksum, part);
            int lastProgramDigit = lower.Length - 7;
            int bits = (lastProgramDigit - 3) * 5;
            int bytes = bits / 8, padding = bits % 8;
            if (bytes < 2 || bytes > 40 || padding >= 5 || (version == 0 && bytes != 20 && bytes != 32)) return false;
            for (int i = 3; i < lower.Length; i++)
            {
                int part = Bech32.IndexOf(lower[i]);
                if (part < 0 || (i == lastProgramDigit && (part & ((1 << padding) - 1)) != 0)) return false;
                checksum = Step(checksum, part);
            }
            return checksum == (version == 0 ? 1u : 0x2bc830a3u);
        }
    }
}
