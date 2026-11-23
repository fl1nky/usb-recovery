using System;
using System.Runtime.Serialization.Json;
using System.Text.RegularExpressions;
using System.Xml;

namespace UsbRecovery
{
    internal static class ElectrumWalletProbe
    {
        // JSON has no reliable image signature. Only classify a complete, bounded
        // recovered file, using top-level public format fields and their types.
        internal static bool Matches(byte[] bytes, int offset, int count)
        {
            if (!HasSingleObject(bytes, offset, count)) return false;
            var quotas = new XmlDictionaryReaderQuotas { MaxDepth = 48, MaxStringContentLength = 1024 * 1024,
                MaxNameTableCharCount = 65536 };
            bool version = false, type = false, structure = false;
            try
            {
                using (var reader = JsonReaderWriterFactory.CreateJsonReader(bytes, offset, count, quotas))
                {
                    reader.MoveToContent();
                    if (reader.GetAttribute("type") != "object") return false;
                    reader.ReadStartElement();
                    while (reader.MoveToContent() == XmlNodeType.Element)
                    {
                        string name = reader.LocalName, kind = reader.GetAttribute("type");
                        if (name == "wallet_type" && kind == "string")
                        {
                            string value = reader.ReadElementContentAsString();
                            type = value == "old" || value == "standard" || value == "imported" ||
                                   value == "2fa" || Regex.IsMatch(value, @"^\d{1,2}of\d{1,2}$");
                        }
                        else if (name == "seed_version" && kind == "number")
                        {
                            int number;
                            version = Int32.TryParse(reader.ReadElementContentAsString(), out number) && number > 0 && number < 1000;
                        }
                        else
                        {
                            if ((name == "keystore" || name == "accounts" || name == "master_public_keys" ||
                                 name == "addresses") && kind == "object") structure = true;
                            reader.Skip();
                        }
                    }
                    reader.ReadEndElement();
                    return reader.MoveToContent() == XmlNodeType.None && version && type && structure;
                }
            }
            catch (XmlException) { return false; }
            catch (System.Runtime.Serialization.SerializationException) { return false; }
        }

        // The framework JSON reader can return a complete root for a truncated
        // document. Verify the actual outer boundary, respecting quoted braces.
        static bool HasSingleObject(byte[] bytes, int offset, int count)
        {
            if (count < 2 || bytes[offset] != '{') return false;
            int depth = 0, end = offset + count;
            bool quoted = false, escaped = false;
            for (int i = offset; i < end; i++)
            {
                byte ch = bytes[i];
                if (quoted)
                {
                    if (escaped) escaped = false;
                    else if (ch == '\\') escaped = true;
                    else if (ch == '"') quoted = false;
                    continue;
                }
                if (ch == '"') quoted = true;
                else if (ch == '{' || ch == '[') depth++;
                else if (ch == '}' || ch == ']')
                {
                    if (--depth != 0) continue;
                    if (ch != '}') return false;
                    for (int j = i + 1; j < end; j++)
                        if (bytes[j] != 32 && bytes[j] != 9 && bytes[j] != 10 && bytes[j] != 13) return false;
                    return true;
                }
            }
            return false;
        }
    }
}
