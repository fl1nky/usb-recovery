using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace UsbRecovery
{
    public static class TelegramEvidenceExport
    {
        public static void WriteFragmentsCsv(TextWriter writer, IEnumerable<TelegramTextFragment> fragments)
        {
            if (writer == null) throw new ArgumentNullException("writer");
            writer.WriteLine("EvidenceKind,SourcePath,SourceOrigin,Offset,PageNumber,SqliteRowId,ColumnIndex,Text");
            if (fragments == null) return;
            foreach (var fragment in fragments)
            {
                if (fragment == null) continue;
                string[] fields = {
                    fragment.EvidenceKind, fragment.SourcePath, fragment.SourceOrigin,
                    fragment.Offset.ToString(CultureInfo.InvariantCulture),
                    fragment.PageNumber.ToString(CultureInfo.InvariantCulture),
                    fragment.SqliteRowId.HasValue ? fragment.SqliteRowId.Value.ToString(CultureInfo.InvariantCulture) : null,
                    fragment.ColumnIndex.ToString(CultureInfo.InvariantCulture), fragment.Text
                };
                for (int i = 0; i < fields.Length; i++)
                {
                    if (i > 0) writer.Write(',');
                    string value = fields[i] ?? String.Empty;
                    // Spreadsheet-safe presentation; JSON retains the exact source text.
                    if (value.Length > 0 && "=+-@\t\r\n".IndexOf(value[0]) >= 0) value = "'" + value;
                    writer.Write('"');
                    writer.Write(value.Replace("\"", "\"\""));
                    writer.Write('"');
                }
                writer.WriteLine();
            }
        }
    }
}
