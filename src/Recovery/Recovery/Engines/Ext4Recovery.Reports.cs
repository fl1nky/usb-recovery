using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class ReportProgress
        {
            public int Schema = 1;
            public string Identity, WorkId, Limits, Output;
            public long Bytes;
            public bool Ready, Published;
        }
        // Emit one scalar/record at a time. Large entries do not need a giant
        // JSON string or a growing root checkpoint; field/key order is fixed.
        static void WriteReportValue(TextWriter writer, object value, Context c)
        {
            c.Cancel.ThrowIfCancellationRequested();
            if (value == null) { writer.Write("null"); return; }
            if (value is string)
            { writer.Write(new JavaScriptSerializer { MaxJsonLength = MaximumGroupBlobBytes }.Serialize((string)value)); return; }
            if (value is bool) { writer.Write((bool)value ? "true" : "false"); return; }
            if (value is int || value is uint || value is long)
            { writer.Write(Convert.ToString(value,CultureInfo.InvariantCulture)); return; }
            var dictionary = value as IDictionary;
            if (dictionary != null)
            {
                var keys = dictionary.Keys.Cast<object>().Select(key => key as string).ToArray();
                if (keys.Any(key => key == null)) throw new IOException("EXT4_REPORT_KEY_INVALID");
                Array.Sort(keys,StringComparer.Ordinal); writer.Write('{'); bool comma = false;
                foreach (string key in keys) { if (comma) writer.Write(','); comma = true; WriteReportValue(writer,key,c); writer.Write(':'); WriteReportValue(writer,dictionary[key],c); }
                writer.Write('}'); return;
            }
            var list = value as IEnumerable;
            if (list != null)
            {
                writer.Write('['); bool comma = false;
                foreach (object item in list) { if (comma) writer.Write(','); comma = true; WriteReportValue(writer,item,c); }
                writer.Write(']'); return;
            }
            Type type = value.GetType();
            if (type != typeof(Report) && type != typeof(VolumeReport) && type != typeof(Entry) && type != typeof(Extent) && type != typeof(NameLink))
                throw new IOException("EXT4_REPORT_TYPE_UNSUPPORTED");
            writer.Write('{'); bool separator = false;
            foreach (var field in type.GetFields(BindingFlags.Instance|BindingFlags.Public).OrderBy(x => x.Name,StringComparer.Ordinal))
            {
                if (separator) writer.Write(','); separator = true; WriteReportValue(writer,field.Name,c); writer.Write(':'); WriteReportValue(writer,field.GetValue(value),c);
            }
            writer.Write('}');
        }
        static void WriteReportStream(Stream stream, Context c)
        {
            using (var writer = new StreamWriter(stream,new UTF8Encoding(false,true),64*1024,true))
            { WriteReportValue(writer,c.Report,c); writer.Flush(); }
        }
        static string ReportIdentity(Context c)
        {
            using (var hash = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,hash,CryptoStreamMode.Write))
            { WriteReportStream(stream,c); stream.FlushFinalBlock(); return Hex(hash.Hash); }
        }
        static string ReportWork(RecoveryCheckpointContext context, string id)
        {
            if (id == null || id.Length != 32 || id.Any(x => !(x >= '0' && x <= '9' || x >= 'a' && x <= 'f')))
                throw new IOException("EXT4_REPORT_WORK_INVALID");
            return RecoveryCatalog.SafeFile(context.Directory,"ext4.state/report-work/"+id+".partial");
        }
        static bool CheckReportFile(string path,string identity,long bytes,Context c)
        {
            NoLinks(path); if (Directory.Exists(path)) throw new IOException("EXT4_REPORT_OUTPUT_CHANGED");
            if (!File.Exists(path)) return false;
            using (var file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
                if (file.Length != bytes || HashStream(file,c.Cancel) != identity) throw new IOException("EXT4_REPORT_OUTPUT_CHANGED");
            return true;
        }
        static ReportProgress ReportState(ReportProgress state)
        {
            return new ReportProgress { Identity = state.Identity, WorkId = state.WorkId,
                Limits = state.Limits, Output = state.Output, Bytes = state.Bytes,
                Ready = state.Ready, Published = state.Published };
        }
        static void ValidateReportSnapshot(Context c, ReportProgress state)
        {
            c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
            if (ReportIdentity(c) != state.Identity) throw new IOException("EXT4_REPORT_CHANGED_DURING_WRITE");
        }
        static void WriteReportCheckpointed(Context c, RecoveryCheckpointContext context, Action<string> progress)
        {
            using (new MetadataSourceScope(c,context))
            {
                ValidateMetadataSource(c,context); string source = Path.GetFullPath(c.Input.Name), root = Path.GetFullPath(c.Root);
                if (source.Equals(root,StringComparison.OrdinalIgnoreCase) || source.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
                    throw new IOException("EXT4_REPORT_SOURCE_IN_OUTPUT");
                string identity = ReportIdentity(c), destination = RecoveryCatalog.SafeFile(root,"report.json");
                string limits = Ext4LimitsIdentity(c.Limits);
                string output = new Uri(Path.GetFullPath(context.Directory)+Path.DirectorySeparatorChar)
                    .MakeRelativeUri(new Uri(root+Path.DirectorySeparatorChar)).ToString();
                var journal = new RecoveryMethodJournal<ReportProgress>(c.Input.Name,
                    new ReportProgress { Identity = identity, Limits = limits, Output = output },context,c.Cancel);
                var state = journal.Payload;
                if (state.Schema != 1 || state.Identity != identity || state.Limits != limits || state.Output != output ||
                    state.Bytes < 0 || state.Published && !state.Ready || !state.Ready && state.Bytes != 0 ||
                    journal.Resumed && state.WorkId == null ||
                    state.Ready && (state.Bytes == 0 || state.WorkId == null)) throw new IOException("EXT4_REPORT_CHECKPOINT_INVALID");
                if (state.WorkId != null) ReportWork(context,state.WorkId);
                if (File.Exists(destination) || Directory.Exists(destination))
                {
                    if (!state.Ready || !CheckReportFile(destination,identity,state.Bytes,c)) throw new IOException("EXT4_REPORT_OUTPUT_UNPLANNED");
                    ValidateReportSnapshot(c,state);
                    if (!state.Published) { var published = ReportState(state); published.Published = true; journal.Save(published); }
                    return;
                }
                bool existingWork = state.Ready && CheckReportFile(ReportWork(context,state.WorkId),identity,state.Bytes,c);
                if (!existingWork)
                {
                    string id = Guid.NewGuid().ToString("N"), path = ReportWork(context,id);
                    Directory.CreateDirectory(Path.GetDirectoryName(path));
                    using (var file = new FileStream(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read))
                    {
                        // Unconfirmed earlier attempts are preserved, not blindly
                        // truncated/deleted. Re-emission uses metadata, not scans.
                        var pending = ReportState(state); pending.WorkId = id; pending.Bytes = 0; pending.Ready = pending.Published = false;
                        journal.Save(pending); state = pending;
                        if (progress != null) progress("ext4: report pending");
                        WriteReportStream(file,c); file.Flush(true);
                        if (HashStream(file,c.Cancel) != identity) throw new IOException("EXT4_REPORT_CHANGED_DURING_WRITE");
                        c.CheckpointSource.ValidateLimits();
                        var ready = ReportState(state); ready.Bytes = file.Length; ready.Ready = true;
                        journal.Save(ready); state = ready;
                        if (progress != null) progress("ext4: report ready");
                    }
                }
                ValidateReportSnapshot(c,state);
                Directory.CreateDirectory(root); File.Move(ReportWork(context,state.WorkId),destination);
                if (!CheckReportFile(destination,identity,state.Bytes,c)) throw new IOException("EXT4_REPORT_OUTPUT_MISSING");
                var complete = ReportState(state); complete.Published = true;
                journal.Save(complete); if (progress != null) progress("ext4: report published"); c.Cancel.ThrowIfCancellationRequested();
            }
        }
    }
}
