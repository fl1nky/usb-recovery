using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class ArchiveMessage
    {
        public string app, snapshot_id, chat_name, sender_name, evidence_kind, source_file, source_record, text;
        public string source_id, original_relative_path, source_sha256;
        public string record_kind, completeness, text_field, native_postbox_value_sha256;
        public string recovery_status,deletion_interpretation,physical_source,record_sha256,proof,native_tl_body_sha256;
        public string provenance_verification;
        public Dictionary<string,object> archive_claims;
        public Dictionary<string,object>[] residual_sources;
        public object sqlite_page,record_page_offset,blob_page_offset,record_length,physical_byte_offset,wal_frame,candidate_message_id,candidate_peer,candidate_date;
        public object sqlite_stored_mid;
        public string sqlite_region,offset_kind,sqlite_record_sha256;
        public object sqlite_record_page_offset,sqlite_record_length,sqlite_blob_page_offset;
        public bool? sqlite_header_length_reconstructed;
        public string sqlite_payload_sha256;
        public object sqlite_payload_length;
        public Dictionary<string,object>[] sqlite_payload_ranges;
        public long[] sqlite_overflow_pages;
        public bool? sqlite_overflow_chain_verified;
        public string heap_class,heap_object_id,heap_record_sha256,heap_text_sha256,heap_version;
        public object candidate_sender,heap_record_length,heap_snapshot_ms,heap_identifier_bytes;
        public bool? header_length_reconstructed,deleted;
        public string identity_scope, native_constructor, wal_proof, wal_db_sha256, wal_sha256, wal_snapshot_sha256;
        public string wal_tail_reason;
        public object wal_validated_prefix_bytes;
        public bool? wal_snapshot_latest_known_commit,wal_current_state_confirmed;
        public string rollback_journal_sha256,rollback_snapshot_sha256,rollback_proof;
        public string container_sha256,container_source_id,container_source_file;
        public string rollback_page_map,rollback_page_map_sha256,rollback_hot_state,rollback_checksum_kind;
        public string rollback_parse_status,rollback_tail_reason,rollback_payload_sha256;
        public object rollback_initial_pages,rollback_validated_prefix_bytes,rollback_header_offset,rollback_record_offset,rollback_page,rollback_payload_length;
        public bool? rollback_current_state_confirmed,rollback_content_authenticity_verified,rollback_payload_chain_verified;
        public Dictionary<string,object>[] rollback_payload_ranges;
        public string media_kind,media_id,media_status;
        public object thumbnail_count;
        public object native_layer, wal_commit_frame;
        public object byte_offset, byte_length;
        public string encoding;
        public string archive_record_key;
        public long text_offset,text_end,match_offset,match_end;
        public bool? application_confirmed;
        public object chat_id, sender_id, message_id, timestamp, timestamp_raw;
        public bool text_truncated;
        public bool? date_ambiguous, timezone_unknown;
        public long text_length;
        public string[] attachments;
        public Dictionary<string, object>[] sources;
    }

    public class ArchiveResponse
    {
        public string status, code, archive;
    }
    public sealed class ArchiveSearchResult : ArchiveResponse
    {
        public long total, offset;
        public int limit;
        public string[] warnings;
        public List<ArchiveMessage> records;
    }
    public sealed class ArchiveTextPage : ArchiveResponse
    {
        public string record_key,text;
        public long text_offset,next_offset,text_length;
        public int limit;
        public bool eof;
    }

    public static class ArchiveSearchService
    {
        public const int PageSize = 100;
        public const long LatestWindowLimit = 100000;
        [DllImport("kernel32.dll")] static extern uint GetConsoleCP();
        [DllImport("kernel32.dll")] static extern bool SetConsoleCP(uint cp);
        const int MaxResponse = 64 * 1024 * 1024;
        public static ArchiveSearchResult Search(string archive, string application, string query, string evidence, long offset, CancellationToken cancel)
        { return Search(archive, application, query, evidence, offset, cancel, false); }
        public static ArchiveSearchResult Search(string archive, string application, string query, string evidence, long offset, CancellationToken cancel, bool useRegex)
        {
            return RunRequest<ArchiveSearchResult>(new{protocol=1,operation="search",archive=archive,app="Telegram",query=query??"",query_mode=useRegex?"regex":"literal",evidence=evidence??"",offset=offset,limit=PageSize,sort="latest"},cancel,
                candidate=>ValidSearch(candidate,offset));
        }
        public static ArchiveTextPage ReadPage(string archive,string recordKey,long offset,CancellationToken cancel)
        {
            if(offset<0||offset>4*1024*1024||String.IsNullOrEmpty(recordKey)||recordKey.Length>128)throw new IOException("MESSAGE_REQUEST_INVALID");
            return RunRequest<ArchiveTextPage>(new{protocol=1,operation="message_page",archive=archive,record_key=recordKey,text_offset=offset,limit=65536},cancel,
                candidate=>candidate.status=="complete"&&candidate.record_key==recordKey&&candidate.text_offset==offset&&candidate.limit==65536&&candidate.text!=null&&candidate.text.Length<=131072&&candidate.text_length<=4*1024*1024&&candidate.next_offset>=offset&&candidate.next_offset<=candidate.text_length&&candidate.next_offset-offset<=65536&&candidate.next_offset-offset==CodePoints(candidate.text)&&candidate.eof==(candidate.next_offset==candidate.text_length)&&(candidate.eof||candidate.next_offset>offset));
        }
        static bool ValidSearch(ArchiveSearchResult candidate,long offset)
        {
            if(candidate.total<0||candidate.offset!=offset||candidate.limit!=PageSize||candidate.records==null||candidate.records.Count>PageSize)return false;
            foreach(var message in candidate.records){
                if(message==null||message.app!="Telegram"||message.text==null||message.text.Length>131072)return false;
                if(!DisplayBound(message.source_file)||!DisplayBound(message.source_record)||!DisplayBound(message.source_sha256)||!DisplayBound(message.snapshot_id))return false;
                if(message.container_sha256!=null||message.container_source_id!=null||message.container_source_file!=null){
                    if(!LowerHash(message.container_sha256)||String.IsNullOrEmpty(message.container_source_id)||String.IsNullOrEmpty(message.container_source_file)||
                        !DisplayBound(message.container_source_id)||!DisplayBound(message.container_source_file))return false;
                }
                if(!ValidRollback(message)||!ValidArchiveClaims(message)||!ValidTextFields(message))return false;
                long length=CodePoints(message.text);if(length<0||length>65536)return false;
                if(message.text_truncated&&(message.text_length<=length||message.text_length>4*1024*1024||message.text_offset<0||message.text_end<message.text_offset||message.text_end>message.text_length||message.text_end-message.text_offset!=length||message.match_offset<message.text_offset||message.match_offset>message.text_end||message.match_end<message.match_offset||message.match_end>message.text_length))return false;
            }return true;
        }
        static bool LowerHash(string value)
        {
            if(value==null||value.Length!=64)return false;
            foreach(char character in value)if(!(character>='0'&&character<='9'||character>='a'&&character<='f'))return false;
            return true;
        }
        static bool DisplayBound(string value){return value==null||value.Length<=8192;}
        static bool ValidTextField(string value){return value==null||value=="message"||value=="media.legacy_caption";}
        static bool ValidTextFields(ArchiveMessage message)
        {
            if(!ValidTextField(message.text_field))return false;
            foreach(var sources in new[]{message.sources,message.residual_sources}){
                if(sources==null)continue;
                foreach(var origin in sources){
                    if(origin==null)return false;
                    object field;if(origin.TryGetValue("text_field",out field)&&field!=null&&(!(field is string)||!ValidTextField((string)field)))return false;
                }
            }return true;
        }
        static bool ValidArchiveClaims(ArchiveMessage message)
        {
            if(message.provenance_verification!=null&&message.provenance_verification!="provided_archive_metadata")return false;
            if(message.archive_claims==null)return true;
            if(message.archive_claims.Count>3)return false;
            foreach(var field in message.archive_claims){
                if(field.Key=="deleted"){if(!(field.Value is bool))return false;}
                else if(field.Key!="recovery_status"&&field.Key!="deletion_interpretation"||!(field.Value is string)||CodePoints((string)field.Value)<0||CodePoints((string)field.Value)>4096)return false;
            }return true;
        }
        static bool BoundedInteger(object value,long minimum,long maximum)
        {
            if(!(value is int)&&!(value is long))return false;
            long number=Convert.ToInt64(value,CultureInfo.InvariantCulture);return number>=minimum&&number<=maximum;
        }
        static bool ValidRollback(ArchiveMessage message)
        {
            if(!ValidTextField(message.text_field))return false;
            if(message.rollback_journal_sha256==null)return message.rollback_proof==null&&message.rollback_page_map==null&&message.rollback_payload_ranges==null&&message.rollback_snapshot_sha256==null;
            if(!LowerHash(message.rollback_journal_sha256)||!LowerHash(message.rollback_page_map_sha256)||message.rollback_page_map!="provenance/rollback/"+message.rollback_journal_sha256+".json"||
                message.rollback_hot_state!="unknown"||message.rollback_current_state_confirmed!=false||message.rollback_content_authenticity_verified!=false||message.rollback_checksum_kind!="sqlite_sparse_32bit"||
                !BoundedInteger(message.rollback_initial_pages,1,131072)||message.deleted!=null||
                message.rollback_parse_status!="complete"&&message.rollback_parse_status!="validated_prefix")return false;
            if(message.rollback_tail_reason!=null&&(message.rollback_tail_reason.Length>64||!Regex.IsMatch(message.rollback_tail_reason,"^[a-z_]+$",RegexOptions.CultureInvariant)))return false;
            if(message.rollback_validated_prefix_bytes!=null&&!BoundedInteger(message.rollback_validated_prefix_bytes,0,256*1024*1024))return false;
            if(message.rollback_header_offset!=null&&!BoundedInteger(message.rollback_header_offset,0,256*1024*1024))return false;
            if(message.rollback_record_offset!=null&&!BoundedInteger(message.rollback_record_offset,0,256*1024*1024))return false;
            if(message.rollback_page!=null&&!BoundedInteger(message.rollback_page,1,Convert.ToInt64(message.rollback_initial_pages,CultureInfo.InvariantCulture)))return false;
            bool complete=message.rollback_proof=="all_pages_from_validated_rollback_journal";
            bool archiveText=message.rollback_proof=="archive_text_from_rollback_snapshot";
            if(complete||archiveText){
                if(!LowerHash(message.rollback_snapshot_sha256)||message.rollback_parse_status!="complete"||message.rollback_tail_reason!=null)return false;
                bool typedMessage=message.record_kind=="tl_message"||message.record_kind=="tl_message_caption"&&message.text_field=="media.legacy_caption";
                if(complete&&(message.evidence_kind!="backup"||!typedMessage||message.application_confirmed!=true))return false;
                if(archiveText&&(message.evidence_kind!="fragment"||message.record_kind!="sqlite_rollback_archive_text"||message.application_confirmed!=false||
                    message.chat_id!=null||message.message_id!=null||message.sender_id!=null||message.sender_name!=null||message.timestamp!=null||message.timestamp_raw!=null||
                    message.rollback_payload_ranges!=null||message.rollback_payload_length!=null||message.rollback_payload_sha256!=null||message.rollback_payload_chain_verified!=null))return false;
            }else if((message.rollback_proof!="validated_rollback_page_fragment"&&message.rollback_proof!="validated_rollback_payload_chain")||
                message.evidence_kind!="fragment"||message.rollback_snapshot_sha256!=null||message.chat_id!=null||message.message_id!=null||message.sender_id!=null||message.sender_name!=null||message.timestamp!=null||message.timestamp_raw!=null)return false;
            if(message.rollback_payload_ranges==null)return message.rollback_proof!="validated_rollback_payload_chain"&&message.rollback_payload_length==null&&message.rollback_payload_sha256==null&&message.rollback_payload_chain_verified==null;
            if(message.rollback_payload_ranges.Length<2||message.rollback_payload_ranges.Length>4096||message.rollback_payload_chain_verified!=true||!LowerHash(message.rollback_payload_sha256)||!BoundedInteger(message.rollback_payload_length,1,4*1024*1024))return false;
            long position=0;var pages=new HashSet<long>();var physical=new List<Tuple<long,long>>();
            foreach(var range in message.rollback_payload_ranges){
                object logical,amount,page,source,offset;
                if(range==null||range.Count!=5||!range.TryGetValue("logical_offset",out logical)||!range.TryGetValue("bytes",out amount)||!range.TryGetValue("sqlite_page",out page)||!range.TryGetValue("physical_source",out source)||!range.TryGetValue("physical_byte_offset",out offset)||
                    !BoundedInteger(logical,position,position)||!BoundedInteger(amount,1,65536)||!BoundedInteger(page,1,Convert.ToInt64(message.rollback_initial_pages,CultureInfo.InvariantCulture))||
                    !(source is string)||(string)source!="rollback_journal"||!BoundedInteger(offset,0,256*1024*1024-Convert.ToInt64(amount,CultureInfo.InvariantCulture))||!pages.Add(Convert.ToInt64(page,CultureInfo.InvariantCulture)))return false;
                long size=Convert.ToInt64(amount,CultureInfo.InvariantCulture),start=Convert.ToInt64(offset,CultureInfo.InvariantCulture);position+=size;physical.Add(Tuple.Create(start,start+size));
            }
            physical.Sort((first,second)=>first.Item1.CompareTo(second.Item1));
            for(int index=1;index<physical.Count;index++)if(physical[index-1].Item2>physical[index].Item1)return false;
            return position==Convert.ToInt64(message.rollback_payload_length,CultureInfo.InvariantCulture);
        }
        static long CodePoints(string text)
        {
            long count=0;for(int index=0;index<text.Length;index++,count++){
                if(Char.IsHighSurrogate(text[index])){if(index+1>=text.Length||!Char.IsLowSurrogate(text[index+1]))return -1;index++;}
                else if(Char.IsLowSurrogate(text[index]))return -1;
            }return count;
        }
        static bool JsonUnicode(string text)
        {
            for(int index=0;index<text.Length;index++){
                if(text[index]=='\\'){
                    if(++index>=text.Length)return false;
                    if(text[index]!='u')continue;
                    int value;if(index+4>=text.Length||!Int32.TryParse(text.Substring(index+1,4),NumberStyles.HexNumber,CultureInfo.InvariantCulture,out value))return false;index+=4;
                    if(value>=0xdc00&&value<=0xdfff)return false;
                    if(value>=0xd800&&value<=0xdbff){
                        int following;if(index+6>=text.Length||text[index+1]!='\\'||text[index+2]!='u'||!Int32.TryParse(text.Substring(index+3,4),NumberStyles.HexNumber,CultureInfo.InvariantCulture,out following)||following<0xdc00||following>0xdfff)return false;index+=6;
                    }
                }else if(Char.IsHighSurrogate(text[index])){if(index+1>=text.Length||!Char.IsLowSurrogate(text[index+1]))return false;index++;}
                else if(Char.IsLowSurrogate(text[index]))return false;
            }return true;
        }
        static T RunRequest<T>(object request,CancellationToken cancel,Func<T,bool> valid) where T:ArchiveResponse
        {
            cancel.ThrowIfCancellationRequested();
            string executable = HelperClient.Executable;
            if (!File.Exists(executable)) throw new IOException("HELPER_MISSING");
            var serializer = new JavaScriptSerializer { MaxJsonLength = MaxResponse };
            using (var process = new Process())
            using (var job = new ProcessJob())
            {
                process.StartInfo = new ProcessStartInfo(executable) { Arguments = "", WorkingDirectory = Path.GetDirectoryName(executable), UseShellExecute = false,
                    RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = new UTF8Encoding(false,true), StandardErrorEncoding = Encoding.UTF8, CreateNoWindow = true };
                uint oldCp = GetConsoleCP();
                try {
                    if (oldCp == 65001) SetConsoleCP(28591);
                    process.Start();
                }
                finally {
                    if (oldCp == 65001) SetConsoleCP(oldCp);
                }
                try { job.Attach(process); } catch { throw new IOException("HELPER_START_FAILED"); }
                T result = null;
                Task errors = Task.Run(() => { var buffer = new char[4096]; while (process.StandardError.Read(buffer, 0, buffer.Length) > 0) { } });
                Task output = Task.Run(() => {
                    string line;
                    while ((line = BoundedLine(process.StandardOutput)) != null)
                    {
                        try {
                            if(!JsonUnicode(line))continue;
                            var header = serializer.Deserialize<Dictionary<string, object>>(line);
                            object type, protocol;
                            if (header == null || !header.TryGetValue("type", out type) || Convert.ToString(type) != "result" || !header.TryGetValue("protocol", out protocol) || Convert.ToInt32(protocol) != 1 || result != null) continue;
                            var candidate = serializer.Deserialize<T>(line);
                            if (candidate.status != "complete" && candidate.status != "partial" && candidate.status != "error") continue;
                            if (!Regex.IsMatch(candidate.code ?? "", "^[A-Z_]{2,40}$")) candidate.code = "SEARCH_FAILED";
                            if (candidate.status != "error" && !valid(candidate)) continue;
                            result = candidate;
                        } catch { }
                    }
                });
                using (cancel.Register(() => job.Stop()))
                {
                    try {
                        var preambleField = typeof(StreamWriter).GetField("haveWrittenPreamble", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic) ?? typeof(StreamWriter).GetField("_haveWrittenPreamble", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                        if (preambleField != null) preambleField.SetValue(process.StandardInput, true);
                        byte[] input = new UTF8Encoding(false).GetBytes(serializer.Serialize(request) + "\n");
                        try{process.StandardInput.BaseStream.Write(input, 0, input.Length); process.StandardInput.BaseStream.Flush();}finally{Array.Clear(input,0,input.Length);process.StandardInput.Close();}
                        while (!process.WaitForExit(200)){cancel.ThrowIfCancellationRequested();if(output.IsFaulted||errors.IsFaulted)throw new IOException("SEARCH_PROTOCOL_ERROR");}
                        Task.WaitAll(output, errors); cancel.ThrowIfCancellationRequested();
                        if (result == null || (process.ExitCode != 0 && result.status != "error")) throw new IOException("SEARCH_PROTOCOL_ERROR");
                        return result;
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { cancel.ThrowIfCancellationRequested(); throw new IOException("SEARCH_FAILED"); }
                    finally { job.Stop(); try { Task.WaitAll(new[] { output, errors }, 3000); } catch { } }
                }
            }
        }

        static string BoundedLine(StreamReader reader)
        {
            var builder = new StringBuilder(); int value;
            while ((value = reader.Read()) >= 0) {
                if (value == 10) return builder.ToString();
                if (value != 13 && builder.Length < MaxResponse) builder.Append((char)value);
                else if (builder.Length >= MaxResponse) { while ((value = reader.Read()) >= 0 && value != 10) { } return ""; }
            }
            return builder.Length == 0 ? null : builder.ToString();
        }

        public static string VerifiedAttachment(string archive, string relative)
        {
            // The generated archive stores original attachments under their content hash.
            // Only explicit, known media/document extensions may be launched by the UI.
            var match = Regex.Match(relative ?? "", "^media/([a-f0-9]{64})\\.(jpg|jpeg|png|webp|heic|heif|gif|bmp|tif|tiff|mp4|mov|m4a|mp3|ogg|wav|pdf|txt)$", RegexOptions.CultureInvariant);
            if (!match.Success) throw new IOException("ATTACHMENT_UNSAFE");
            string root = Path.GetFullPath(archive), full = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!full.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("ATTACHMENT_UNSAFE");
            for (var item = new DirectoryInfo(root); item != null; item = item.Parent) if (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("ATTACHMENT_UNSAFE");
            for (var item = new FileInfo(full).Directory; item != null && item.FullName.StartsWith(root, StringComparison.OrdinalIgnoreCase); item = item.Parent) if ((item.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("ATTACHMENT_UNSAFE");
            var file = new FileInfo(full);
            if (!file.Exists) throw new IOException("ATTACHMENT_MISSING");
            if ((file.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("ATTACHMENT_UNSAFE");
            using (var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create()) {
                string hash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                if (!String.Equals(hash, match.Groups[1].Value, StringComparison.Ordinal)) throw new IOException("ATTACHMENT_CHANGED");
            }
            return full;
        }
    }

    internal sealed class TelegramDesktopAccessForm : Form
    {
        readonly TextBox passcode=new TextBox();
        readonly CheckBox unprotected=new CheckBox();
        public TelegramDesktopAccessForm(string current)
        {
            Text="Локальный код Telegram Desktop";ClientSize=new Size(440,236);FormBorderStyle=FormBorderStyle.FixedDialog;
            MaximizeBox=MinimizeBox=false;ShowInTaskbar=false;StartPosition=FormStartPosition.CenterParent;Font=new Font("Segoe UI",10F);
            var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(18),ColumnCount=1,RowCount=5};Controls.Add(layout);
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,52));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,35));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,35));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,36));
            layout.Controls.Add(new Label{Text="Укажи известный локальный код приложения Desktop для чтения сохранившихся черновиков.",AutoSize=true,MaximumSize=new Size(400,0)},0,0);
            passcode.Name="telegram-desktop-passcode";passcode.UseSystemPasswordChar=true;passcode.MaxLength=4096;passcode.Dock=DockStyle.Fill;layout.Controls.Add(passcode,0,1);
            unprotected.Name="telegram-desktop-unprotected";unprotected.Text="В выбранном Desktop нет локального кода";unprotected.AutoSize=true;layout.Controls.Add(unprotected,0,2);
            layout.Controls.Add(new Label{Text="Код действует только для этого анализа и не сохраняется.",AutoSize=true,MaximumSize=new Size(400,0),ForeColor=Color.DimGray},0,3);
            var actions=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,WrapContents=false};
            var accept=new Button{Text="Применить",DialogResult=DialogResult.OK,AutoSize=true};var cancel=new Button{Text="Отмена",DialogResult=DialogResult.Cancel,AutoSize=true};
            actions.Controls.Add(accept);actions.Controls.Add(cancel);layout.Controls.Add(actions,0,4);AcceptButton=accept;CancelButton=cancel;
            passcode.TextChanged+=delegate{if(passcode.TextLength>0)unprotected.Checked=false;};
            unprotected.CheckedChanged+=delegate{if(unprotected.Checked)passcode.Clear();passcode.Enabled=!unprotected.Checked;};
            if(current!=null){if(current.Length==0)unprotected.Checked=true;else passcode.Text=current;}
            Disposed+=delegate{passcode.Clear();};
        }
        internal string KnownPasscode { get { return unprotected.Checked?"":passcode.TextLength>0?passcode.Text:null; } }
    }

    public sealed class ArchiveSearchPanel : UserControl
    {
        readonly TextBox archive = new TextBox(), query = new TextBox(), body = new TextBox(), provenance = new TextBox();
        readonly ComboBox evidence = new ComboBox(), attachments = new ComboBox();
        readonly Button choose = new Button(), analyze = new Button(), search = new Button(), previous = new Button(), next = new Button(), cancelButton = new Button(), openAttachment = new Button(), copy = new Button(), fullText = new Button();
        readonly Label count = new Label();
        readonly TextBox analysisStatus = new TextBox();
        readonly RecoveryActivityView analysisActivity=new RecoveryActivityView();
        readonly Panel analysisState=new Panel();
        TableLayoutPanel contentLayout;
        readonly CheckBox regexMode = new CheckBox();
        readonly Button analysisSource = new Button(), desktopAccess = new Button();
        string desktopKnownPasscode;
        readonly DataGridView grid = new DataGridView();
        CancellationTokenSource cancellation;
        ArchiveSearchResult current;
        Tuple<string,string,string,bool> currentSearch, pendingSearch;
        bool busy, rerun, analysisBusy;
        long pageOffset;
        public bool IsBusy { get { return busy || analysisBusy; } }
        public string AnalysisSource { get; private set; }
        public string FragmentQuery { get { return query.Text; } }
        public bool UseRegex { get { return regexMode.Checked; } }
        public event EventHandler AnalyzeRequested;
        public event EventHandler AnalysisCancelRequested;

        public ArchiveSearchPanel()
        {
            Dock = DockStyle.Fill; BackColor = Color.FromArgb(246, 246, 246); Font = new Font("Segoe UI", 10F);
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), ColumnCount = 1, RowCount = 8 };contentLayout=layout;
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 78)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 98));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 145)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80)); Controls.Add(layout);
            var heading = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0, 0, 0, 14) };
            heading.RowStyles.Add(new RowStyle(SizeType.Absolute, 40)); heading.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            heading.Controls.Add(new Label { Text = "Telegram", Font = new Font("Segoe UI", 20F, FontStyle.Bold), AutoSize = true, Margin = new Padding(0) }, 0, 0);
            heading.Controls.Add(new Label { Text = "Локальные данные и последние доступные переписки", AutoSize = true, Tag = "muted", Margin = new Padding(0, 4, 0, 0) }, 0, 1); layout.Controls.Add(heading, 0, 0);
            var folders = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 5, Margin = new Padding(0, 0, 0, 10) };
            folders.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 158)); folders.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 132)); folders.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));folders.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,132)); folders.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Configure(analyze, "Анализировать", delegate { if (IsBusy) return; var handler = AnalyzeRequested; if (handler != null) handler(this, EventArgs.Empty); }); analyze.Tag = "primary"; analyze.Name = "telegram-analyze"; folders.Controls.Add(analyze, 0, 0);
            Configure(analysisSource, "Источник…", delegate { ChooseAnalysisSource(); }); analysisSource.Name = "telegram-source"; folders.Controls.Add(analysisSource, 1, 0);
            Configure(choose, "Открыть архив", delegate { ChooseArchive(); }); folders.Controls.Add(choose, 2, 0);
            Configure(desktopAccess,"Код Desktop…",delegate{using(var dialog=new TelegramDesktopAccessForm(desktopKnownPasscode)){if(dialog.ShowDialog(this)==DialogResult.OK){desktopKnownPasscode=dialog.KnownPasscode;desktopAccess.Text=desktopKnownPasscode==null?"Код Desktop…":"Код выбран";}}});desktopAccess.Name="telegram-desktop-access";folders.Controls.Add(desktopAccess,3,0);
            archive.ReadOnly = true; archive.Dock = DockStyle.Fill; archive.Font = new Font("Consolas", 9F); archive.Margin = new Padding(8, 5, 0, 0); archive.Name = "telegram-archive"; folders.Controls.Add(archive, 4, 0); layout.Controls.Add(folders, 0, 1);
            analysisStatus.Multiline = true; analysisStatus.ReadOnly = true; analysisStatus.Dock = DockStyle.Fill; analysisStatus.ScrollBars = ScrollBars.Vertical; analysisStatus.Name = "telegram-analysis-status"; analysisStatus.Tag = "muted"; analysisStatus.Margin = new Padding(0, 3, 0, 8);
            analysisStatus.Text = "Нажми «Анализировать»: программа найдёт доступные локальные данные Telegram. Закрытый кэш будет отмечен отдельно.";analysisState.Dock=DockStyle.Fill;analysisState.Margin=Padding.Empty;analysisActivity.Dock=DockStyle.Fill;analysisActivity.Name="telegram-activity";analysisActivity.Visible=false;analysisState.Controls.Add(analysisStatus);analysisState.Controls.Add(analysisActivity);layout.Controls.Add(analysisState, 0, 2);
            var filters = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3, RowCount = 3, Margin = new Padding(0) };
            filters.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); filters.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 185)); filters.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 115));
            filters.Controls.Add(new Label { Text = "Ключевые слова", AutoSize = true, Margin = new Padding(0, 0, 0, 5) }, 0, 0);
            filters.Controls.Add(new Label { Text = "Категория", AutoSize = true }, 1, 0);
            query.Dock = DockStyle.Fill; query.Font = new Font("Segoe UI", 11F); query.MaxLength = 1024; query.Name = "telegram-keywords"; query.Margin = new Padding(0, 3, 8, 0); query.KeyDown += delegate(object sender, KeyEventArgs e) { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; StartSearch(0); } }; filters.Controls.Add(query, 0, 1);
            evidence.DropDownStyle = ComboBoxStyle.DropDownList; evidence.Items.AddRange(new object[] { "Все категории", "Из экспорта", "Из резервной копии", "Предыдущая версия", "Текстовый фрагмент", "Удалённые записи (остатки)" }); evidence.SelectedIndex = 0; evidence.Dock = DockStyle.Fill; filters.Controls.Add(evidence, 1, 1);
            Configure(search, "Найти", delegate { StartSearch(0); }); search.Name = "telegram-search"; filters.Controls.Add(search, 2, 1);
            var hints = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false, Margin = new Padding(0, 3, 0, 0) };
            regexMode.Text = "Regex"; regexMode.AutoSize = true; regexMode.Name = "telegram-regex"; hints.Controls.Add(regexMode);
            hints.Controls.Add(new Label { Text = "Например: рецепт|пирожк.*  ·  Без Regex ищутся все слова", AutoSize = true, ForeColor = Color.FromArgb(105, 105, 105), Margin = new Padding(8, 3, 0, 0) });
            filters.Controls.Add(hints, 0, 2); filters.SetColumnSpan(hints, 3); layout.Controls.Add(filters, 0, 3);
            var paging = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, Margin = new Padding(0, 3, 0, 3) };
            paging.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); for (int i = 0; i < 3; i++) paging.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
            count.Text = "Анализ ещё не выполнен"; count.AutoSize = true; count.Anchor = AnchorStyles.Left; paging.Controls.Add(count, 0, 0);
            Configure(previous, "← Назад", delegate { StartSearch(Math.Max(0, pageOffset - ArchiveSearchService.PageSize)); }); Configure(next, "Далее →", delegate { StartSearch(pageOffset + ArchiveSearchService.PageSize); }); Configure(cancelButton, "Остановить", delegate { if (analysisBusy) { var handler = AnalysisCancelRequested; if (handler != null) handler(this, EventArgs.Empty); } else if (cancellation != null) cancellation.Cancel(); }); cancelButton.Name = "telegram-stop";
            previous.Enabled = next.Enabled = cancelButton.Enabled = false; paging.Controls.Add(previous, 1, 0); paging.Controls.Add(next, 2, 0); paging.Controls.Add(cancelButton, 3, 0); layout.Controls.Add(paging, 0, 4);
            grid.Dock = DockStyle.Fill; grid.ReadOnly = true; grid.AllowUserToAddRows = grid.AllowUserToDeleteRows = grid.AllowUserToResizeRows = false; grid.MultiSelect = false; grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect; grid.RowHeadersVisible = false; grid.AutoGenerateColumns = false; grid.BorderStyle = BorderStyle.FixedSingle; grid.BackgroundColor = Color.White; grid.GridColor = Color.FromArgb(224, 224, 224); grid.EnableHeadersVisualStyles = false; grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(239, 239, 239); grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(35, 35, 35); grid.ColumnHeadersHeight = 36; grid.RowTemplate.Height = 34;
            Column("chat", "Чат", 125); Column("author", "Автор", 125); Column("date", "Дата", 150); Column("category", "Категория", 130); Column("text", "Сообщение", 200); grid.Columns[4].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            grid.Name = "telegram-messages"; grid.SelectionChanged += delegate { ShowMessage(); }; layout.Controls.Add(grid, 0, 5);
            var selected = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0, 10, 0, 0) };
            selected.RowStyles.Add(new RowStyle(SizeType.Absolute, 38)); selected.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 5 };
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 155)); actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170)); actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125));actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,110));
            actions.Controls.Add(new Label { Text = "Выбранное сообщение", AutoSize = true }, 0, 0); Configure(copy, "Копировать текст", delegate { if (!String.IsNullOrEmpty(body.Text)) { try { Clipboard.SetText(body.Text); } catch { } } }); actions.Controls.Add(copy, 1, 0);
            attachments.DropDownStyle = ComboBoxStyle.DropDownList; attachments.Dock = DockStyle.Fill; actions.Controls.Add(attachments, 2, 0); Configure(openAttachment, "Вложение", delegate { OpenAttachment(); }); actions.Controls.Add(openAttachment, 3, 0);Configure(fullText,"Полный текст",delegate{OpenFullText();});fullText.Name="telegram-full-text";fullText.Enabled=false;actions.Controls.Add(fullText,4,0);selected.Controls.Add(actions, 0, 0);
            body.Multiline = true; body.ReadOnly = true; body.HideSelection = false; body.ScrollBars = ScrollBars.Vertical; body.Dock = DockStyle.Fill; body.BackColor = Color.White; selected.Controls.Add(body, 0, 1); layout.Controls.Add(selected, 0, 6);
            provenance.Multiline = true; provenance.ReadOnly = true; provenance.ScrollBars = ScrollBars.Vertical; provenance.Dock = DockStyle.Fill; provenance.BackColor = Color.FromArgb(246, 246, 246); provenance.BorderStyle = BorderStyle.None; provenance.Margin = new Padding(0, 8, 0, 0); layout.Controls.Add(provenance, 0, 7);
            copy.Enabled = openAttachment.Enabled = false; Disposed += delegate { desktopKnownPasscode=null;if (cancellation != null) cancellation.Cancel(); };
            UiTheme.ApplyTree(this); analysisStatus.BackColor = UiTheme.Background; analysisStatus.ForeColor = UiTheme.Muted; analysisStatus.BorderStyle = BorderStyle.None;
        }

        void Column(string name, string title, int width) { grid.Columns.Add(new DataGridViewTextBoxColumn { Name = name, HeaderText = title, Width = width, SortMode = DataGridViewColumnSortMode.NotSortable }); }
        static void Configure(Button button, string label, EventHandler click) { button.Text = label; button.Dock = DockStyle.Fill; button.FlatStyle = FlatStyle.Flat; button.FlatAppearance.BorderColor = Color.FromArgb(205, 205, 205); button.MinimumSize = new Size(0, 28); button.Click += click; }
        // Kept for callers opening an older archive. This screen always searches Telegram.
        public void SetApplication(string name) { }
        public void SetAnalysisBusy(bool value, string message)
        {
            if (value && busy) throw new InvalidOperationException("SEARCH_IN_PROGRESS");
            analysisBusy = value;
            if (!String.IsNullOrEmpty(message)) analysisStatus.Text = message;
            analysisActivity.IsActive=value;analysisActivity.SetPhase("Анализ Telegram",message??"Чтение доступных локальных файлов");analysisActivity.Visible=value;analysisStatus.Visible=!value;
            if(contentLayout!=null)contentLayout.RowStyles[2].Height=value?124:50;
            if(value)analysisActivity.BringToFront();else analysisStatus.BringToFront();
            if (value) { ClearResults(); archive.Clear(); count.Text = "Анализ локальных данных…"; }
            SetBusy(busy || analysisBusy);
        }
        public void CompleteAnalysis(string path, string summary)
        {
            SetAnalysisBusy(false, summary);
            if (String.IsNullOrEmpty(path)) { ClearResults(); count.Text = "Доступные сообщения не найдены"; return; }
            SelectArchive(path);
        }
        public void ShowAnalysisError(string message)
        {
            SetAnalysisBusy(false, message); ClearResults(); count.Text = "Анализ не завершён";
        }
        public void SelectArchive(string path) { if (File.Exists(path)) path = Path.GetDirectoryName(path); archive.Text = path ?? ""; if (busy) { rerun = true; if (cancellation != null) cancellation.Cancel(); } else if (IsHandleCreated) StartSearch(0); }
        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); if (!String.IsNullOrEmpty(archive.Text)) BeginInvoke(new Action(() => StartSearch(0))); }
        public void FocusQuery() { query.Focus(); }
        public Dictionary<string,string> TakeDesktopSecrets()
        {
            var result=new Dictionary<string,string>();
            if(desktopKnownPasscode!=null)result["telegram_desktop_passcode"]=desktopKnownPasscode;
            desktopKnownPasscode=null;desktopAccess.Text="Код Desktop…";return result;
        }
        public void SetAnalysisSource(string path) { if (IsBusy) return; AnalysisSource = path; analysisSource.Text = String.IsNullOrEmpty(path) ? "Источник…" : "Источник выбран"; analysisStatus.Text = String.IsNullOrEmpty(path) ? "Автопоиск в локальных папках Telegram." : "Рекурсивный анализ: " + path + ". Поддерживаемые записи базы и текстовые остатки показываются отдельно."; }
        void ChooseAnalysisSource()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Автопоиск на компьютере", null, delegate { SetAnalysisSource(null); });
            menu.Items.Add("Папка / копия телефона…", null, delegate { using (var d = new FolderBrowserDialog { Description = "Локальная копия Telegram или папка с дампами", ShowNewFolderButton = false }) if (d.ShowDialog(this) == DialogResult.OK) SetAnalysisSource(d.SelectedPath); });
            menu.Items.Add("Дамп памяти / файл…", null, delegate { using (var d = new OpenFileDialog { Title = "Предоставленный локальный дамп или база Telegram", Filter = "Дампы и базы|*.dmp;*.dump;*.mem;*.hprof;*.raw;*.bin;*.db;*.sqlite|Все файлы|*.*" }) if (d.ShowDialog(this) == DialogResult.OK) SetAnalysisSource(d.FileName); });
            menu.Closed += delegate { menu.Dispose(); }; menu.Show(analysisSource, new Point(0, analysisSource.Height));
        }
        void ChooseArchive() { using (var dialog = new FolderBrowserDialog { Description = "Готовый архив с chat-index.sqlite или messages.jsonl", ShowNewFolderButton = false, SelectedPath = Directory.Exists(archive.Text) ? archive.Text : "" }) if (dialog.ShowDialog(this) == DialogResult.OK) SelectArchive(dialog.SelectedPath); }

        async void StartSearch(long offset)
        {
            if (IsBusy) return;
            if (String.IsNullOrWhiteSpace(archive.Text)) { count.Text = "Сначала нажми «Анализировать»"; return; }
            string path = archive.Text, app = "Telegram", words = query.Text; bool useRegex = regexMode.Checked;
            string[] categories = { "", "export", "backup", "previous", "fragment", "deleted" }; string category = categories[Math.Max(0, evidence.SelectedIndex)];
            var selection = Tuple.Create(path, words, category, useRegex);
            if (offset > 0 && !selection.Equals(currentSearch)) offset = 0;
            if (offset < 0 || offset > ArchiveSearchService.LatestWindowLimit - ArchiveSearchService.PageSize) { count.Text = ErrorLabel("QUERY_WINDOW_LIMIT"); SetBusy(false); return; }
            pendingSearch = selection;
            cancellation = new CancellationTokenSource(); busy = true; SetBusy(true); count.Text = "Поиск в локальном архиве…";
            CancellationToken token = cancellation.Token;
            ArchiveSearchResult result = null; int failure = 0;
            try {
                // Always marshal completion through this control, including callers
                // that use a nested UI loop without a synchronization context.
                result = await Task.Run(() => ArchiveSearchService.Search(path, app, words, category, offset, token, useRegex)).ConfigureAwait(false);
            } catch (OperationCanceledException) { failure = 1; }
            catch { failure = 2; }
            if (IsDisposed || !IsHandleCreated) { busy = false; if (cancellation != null) { cancellation.Dispose(); cancellation = null; } return; }
            try { BeginInvoke(new Action(() => CompleteSearch(result, failure))); }
            catch (InvalidOperationException) { busy = false; if (cancellation != null) { cancellation.Dispose(); cancellation = null; } }
        }

        void CompleteSearch(ArchiveSearchResult result, int failure)
        {
            try {
                if (IsDisposed) return;
                if (failure == 1) { count.Text = "Поиск остановлен"; return; }
                if (failure == 2 || result == null) { ClearResults(); count.Text = "Не удалось прочитать архив. Проверь папку и готовый комплект программы."; return; }
                if (result.status == "error") { if (result.code != "QUERY_WINDOW_LIMIT") ClearResults(); count.Text = ErrorLabel(result.code); return; }
                current = result; currentSearch = pendingSearch; pageOffset = result.offset; grid.Rows.Clear(); body.Clear(); provenance.Clear();
                foreach (var message in result.records) {
                    if (!String.Equals(message.app, "Telegram", StringComparison.OrdinalIgnoreCase)) throw new IOException("SEARCH_APP_MISMATCH");
                    int row = grid.Rows.Add(Known(message.chat_name, message.chat_id, "Чат неизвестен"), Known(message.sender_name, message.sender_id, "Автор неизвестен"), DisplayDate(message), MessageCategory(message), OneLine(message.media_kind=="photo"&&String.IsNullOrEmpty(message.text)?"Фотография без подписи":message.text,message)); grid.Rows[row].Tag = message;
                }
                long last = Math.Min(result.total, pageOffset + result.records.Count); count.Text = result.total == 0 ? "По запросу ничего не найдено" : "Найдено: " + result.total.ToString("N0") + " · " + (pageOffset + 1) + "–" + last;
                if (result.status == "partial") count.Text += " · есть замечания к архиву";
                if (result.total > ArchiveSearchService.LatestWindowLimit && pageOffset >= ArchiveSearchService.LatestWindowLimit - ArchiveSearchService.PageSize) count.Text += " · уточни запрос";
                if (grid.Rows.Count > 0) { grid.Rows[0].Selected = true; grid.CurrentCell = grid.Rows[0].Cells[0]; } ShowMessage();
            } catch { ClearResults(); count.Text = "Не удалось прочитать архив. Проверь папку и готовый комплект программы."; }
            finally { busy = false; if (cancellation != null) { cancellation.Dispose(); cancellation = null; } if (!IsDisposed) { SetBusy(false); if (rerun) { rerun = false; BeginInvoke(new Action(() => StartSearch(0))); } } }
        }

        void SetBusy(bool value) { desktopAccess.Enabled = analysisSource.Enabled = regexMode.Enabled = choose.Enabled = analyze.Enabled = search.Enabled = query.Enabled = evidence.Enabled = !value; cancelButton.Enabled = value; previous.Enabled = !value && current != null && pageOffset > 0; next.Enabled = !value && current != null && pageOffset >= 0 && pageOffset <= ArchiveSearchService.LatestWindowLimit - 2 * ArchiveSearchService.PageSize && pageOffset + ArchiveSearchService.PageSize < current.total;var selected=grid.SelectedRows.Count==0?null:grid.SelectedRows[0].Tag as ArchiveMessage;fullText.Enabled=!value&&selected!=null&&selected.text_truncated&&!String.IsNullOrEmpty(selected.archive_record_key); }
        void ClearResults() { current = null; currentSearch = null; pageOffset = 0; grid.Rows.Clear(); ShowMessage(); }
        static string Known(string preferred, object fallback, string unknown)
        {
            string result=!String.IsNullOrEmpty(preferred)?preferred:fallback==null||String.IsNullOrEmpty(Convert.ToString(fallback))?unknown:Convert.ToString(fallback);
            if(result.Length<=4096)return result;int end=4096;if(Char.IsHighSurrogate(result[end-1]))end--;return result.Substring(0,end)+"…";
        }
        static string DisplayDate(ArchiveMessage message)
        {
            string value = Known(null, message.timestamp ?? message.timestamp_raw, "Дата неизвестна");
            DateTimeOffset date;
            if (message.timestamp != null && Regex.IsMatch(value, "^[0-9]{4}-[0-9]{2}-[0-9]{2}T") && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out date)) return date.ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture);
            return value;
        }
        string FirstTerm() { var terms = Regex.Split(query.Text.Trim(), "\\s+"); return terms.Length == 0 ? "" : terms[0]; }
        string OneLine(string value,ArchiveMessage message)
        {
            value=(value??"").Replace('\r',' ').Replace('\n',' ');if(value.Length<=300)return value;
            string term=FirstTerm();int match=message.text_truncated&&message.match_offset>=message.text_offset&&message.match_offset<=message.text_end?CodePointIndex(value,message.match_offset-message.text_offset):String.IsNullOrEmpty(term)?-1:value.IndexOf(term,StringComparison.OrdinalIgnoreCase);
            int start=match<0?0:Math.Max(0,match-100);if(start>0&&start<value.Length&&Char.IsLowSurrogate(value[start]))start--;
            int length=Math.Min(300,value.Length-start);if(length>0&&start+length<value.Length&&Char.IsHighSurrogate(value[start+length-1]))length--;
            return(start>0?"…":"")+value.Substring(start,length)+(start+length<value.Length?"…":"");
        }
        static string Category(string value) { switch (value) { case "export": return "Из экспорта"; case "backup": return "Из резервной копии"; case "previous": return "Предыдущая версия"; case "fragment": return "Текстовый фрагмент"; default: return "Категория неизвестна"; } }
        static string MessageCategory(ArchiveMessage message)
        {
            if(message.recovery_status=="imported_recovery_claim")return "Заявлено в архиве";
            if(message.record_kind=="telegram_desktop_draft")return "Черновик Desktop";
            if(message.record_kind=="telegram_android_scheduled"||message.record_kind=="telegram_android_scheduled_caption")return message.evidence_kind=="previous"?"Запланировано · прежняя версия":"Запланировано Android";
            if(message.record_kind=="telegram_ios29_message")return message.evidence_kind=="previous"?"iOS 29 · прежняя версия":"iOS · прежний формат 29";
            if(message.record_kind=="telegram_ios_postbox_message")return message.evidence_kind=="previous"?"iOS Postbox · прежняя версия":"iOS Postbox";
            if(message.record_kind=="telegram_ios_postbox_unsent")return "iOS · неотправленный текст";
            bool caption=message.text_field=="media.legacy_caption"||SupplementalCaption(message.record_kind);
            if(CacheRecord(message.record_kind))return caption?(message.evidence_kind=="previous"?"Кэш · предыдущая подпись":"Кэш · подпись к фото"):(message.evidence_kind=="previous"?"Кэш · предыдущая версия":"Кэш Telegram");
            if(caption)return message.recovery_status=="deleted_supported_by_evidence"?"Подпись к вложению · остаток записи":message.evidence_kind=="previous"?"Подпись к вложению · предыдущая версия":"Подпись к вложению";
            return message.recovery_status=="deleted_supported_by_evidence"?"Остаток записи":message.record_kind=="notification"?"Уведомление":Category(message.evidence_kind);
        }
        static bool CacheRecord(string kind){return kind=="telegram_media_cache"||kind=="telegram_media_cache_caption";}
        static bool SupplementalCaption(string kind){return kind=="tl_message_caption"||kind=="sqlite_deleted_caption"||kind=="telegram_media_cache_caption"||kind=="telegram_android_scheduled_caption";}
        static string TextFieldLabel(string field){return field=="message"?"основной текст":field=="media.legacy_caption"?"подпись к вложению":"неизвестно";}
        static int CodePointIndex(string text,long points)
        {
            int index=0;while(index<text.Length&&points>0){if(Char.IsHighSurrogate(text[index])&&index+1<text.Length&&Char.IsLowSurrogate(text[index+1]))index++;index++;points--;}return index;
        }
        static string DisplayText(string text){return (text??"").Replace("\r\n","\n").Replace('\r','\n').Replace("\n","\r\n");}
        static int DisplayIndex(string text,int original)
        {
            int shown=0;for(int index=0;index<original;index++){
                if(text[index]=='\r'&&index+1<text.Length&&text[index+1]=='\n'){shown++;if(index+1<original){shown++;index++;}}
                else shown+=text[index]=='\r'||text[index]=='\n'?2:1;
            }return shown;
        }
        static Dictionary<string,object> UnconfirmedWalOrigin(ArchiveMessage message)
        {
            if(message.wal_current_state_confirmed==false)return new Dictionary<string,object>{{"wal_tail_reason",message.wal_tail_reason},{"wal_validated_prefix_bytes",message.wal_validated_prefix_bytes}};
            foreach(var origins in new[]{message.sources,message.residual_sources})if(origins!=null)foreach(var origin in origins){
                object value;if(origin!=null&&origin.TryGetValue("wal_current_state_confirmed",out value)&&value is bool&&!(bool)value)return origin;
            }
            return null;
        }
        static string ErrorLabel(string code) { switch (code) { case "REGEX_INVALID": return "Ошибка в регулярном выражении. Исправь запрос или выключи Regex."; case "REGEX_TIMEOUT": return "Регулярное выражение слишком сложное. Сократи запрос."; case "QUERY_WINDOW_LIMIT": return "Доступны первые 100 000 совпадений. Уточни запрос, чтобы найти нужное."; case "ARCHIVE_NOT_FOUND": return "В папке нет готового архива. Нажми «Анализировать» или выбери другую папку."; case "ARCHIVE_INCOMPLETE": return "Этот архив не завершён. Дождись успешного окончания импорта."; case "ARCHIVE_PATH_UNSAFE": return "Выбери обычную папку без ссылок и перенаправлений."; case "ARCHIVE_INDEX_INVALID": case "ARCHIVE_SCHEMA_UNSUPPORTED": return "Индекс архива повреждён или его формат не поддерживается."; case "QUERY_TOO_LONG": case "INVALID_REQUEST": return "Сократи запрос до 32 слов."; case "ARCHIVE_TOO_LARGE": return "Размер индекса превышает поддерживаемый предел."; default: return "Не удалось прочитать архив."; } }
        void ShowMessage()
        {
            var message = grid.SelectedRows.Count == 0 ? null : grid.SelectedRows[0].Tag as ArchiveMessage;
            body.Text = message == null ? "" : DisplayText(message.text); provenance.Clear(); attachments.Items.Clear(); copy.Enabled = message != null; openAttachment.Enabled = false;fullText.Enabled=!IsBusy&&message!=null&&message.text_truncated&&!String.IsNullOrEmpty(message.archive_record_key);copy.Text=message!=null&&message.text_truncated?"Копировать фрагмент":"Копировать текст";
            if (message == null) return;
            string term = FirstTerm(); int location = String.IsNullOrEmpty(term) ? -1 : body.Text.IndexOf(term, StringComparison.OrdinalIgnoreCase); if (location >= 0) { body.Select(location, term.Length); body.ScrollToCaret(); }
            if(message.text_truncated&&message.match_end>message.match_offset&&message.match_offset>=message.text_offset&&message.match_offset<message.text_end){
                string raw=message.text??"";int begin=CodePointIndex(raw,message.match_offset-message.text_offset),end=CodePointIndex(raw,message.match_end-message.text_offset);int shownBegin=DisplayIndex(raw,begin),shownEnd=DisplayIndex(raw,end);body.Select(shownBegin,Math.Max(0,shownEnd-shownBegin));body.ScrollToCaret();}
            var details = new StringBuilder(); details.AppendLine("Источник: " + Known(message.source_file, null, "неизвестен") + " · запись: " + Known(message.source_record, null, "неизвестна"));
            details.AppendLine("Дата записи: " + Known(null, message.timestamp ?? message.timestamp_raw, "неизвестна"));
            details.Append("Снимок: " + Known(message.snapshot_id, null, "неизвестен") + " · ID чата: " + Known(null, message.chat_id, "неизвестен") + " · ID автора: " + Known(null, message.sender_id, "неизвестен") + " · ID сообщения: " + Known(null, message.message_id, "неизвестен"));
            if(message.text_field!=null||SupplementalCaption(message.record_kind))details.AppendLine("\r\nПоле текста: "+TextFieldLabel(message.text_field));
            if(SupplementalCaption(message.record_kind))details.AppendLine("Отдельное поле той же исходной записи, не самостоятельное сообщение. Основной текст и подпись сохранены раздельно.");
            if (!String.IsNullOrEmpty(message.source_sha256)) details.AppendLine("\r\nSHA256 источника: " + message.source_sha256);
            if(message.provenance_verification=="provided_archive_metadata")details.AppendLine("\r\nЗапись импортирована из предоставленного архива. Указанные в нём сведения о происхождении в этом анализе независимо не проверялись.");
            if(message.recovery_status=="imported_recovery_claim"){
                details.AppendLine("\r\nОтметка об удалении перенесена из исходного архива; проверенной находкой удалённой записи в этом анализе она не считается.");
                object status,interpretation;var claims=message.archive_claims;
                if(claims!=null){claims.TryGetValue("recovery_status",out status);claims.TryGetValue("deletion_interpretation",out interpretation);details.AppendLine("Исходная отметка: "+Known(null,status,"не указана")+" · "+Known(null,interpretation,"без пояснения"));}
            }
            if(!String.IsNullOrEmpty(message.container_source_file))details.AppendLine("\r\nАрхив-источник: "+message.container_source_file+" · SHA256: "+message.container_sha256);
            if (message.date_ambiguous == true || message.timezone_unknown == true) details.AppendLine("\r\nДата или часовой пояс требуют уточнения по исходному экспорту.");
            if (message.record_kind == "notification") details.AppendLine("\r\nСохранённый текст уведомления: может содержать только часть сообщения. Полная переписка в источнике может отсутствовать.");
            if(message.record_kind=="telegram_desktop_draft")details.AppendLine("\r\nЛокальный черновик Telegram Desktop: неотправленный текст. Это не история переписки и не удалённое сообщение. Автор, дата создания и ID отправленного сообщения неизвестны; ID ответа внутри черновика не присваивается самому черновику.");
            if(message.record_kind=="telegram_android_scheduled"||message.record_kind=="telegram_android_scheduled_caption")details.AppendLine("\r\nЗапланированная запись Telegram Android. Дата означает время планируемой отправки; отправка и факт удаления не подтверждены.");
            if(message.record_kind=="telegram_ios29_message")details.AppendLine("\r\nИсторическая локальная база Telegram iOS, схема 29. Прочитан исходный текст SQLite; вложения не декодированы. Это не поддержка современных баз Postbox.");
            if(message.record_kind=="telegram_ios_postbox_message"||message.record_kind=="telegram_ios_postbox_unsent")details.AppendLine("\r\nЧитаемая база Postbox 25: текст сообщения связан с индексом истории t4. Вложения и атрибуты не декодированы. Идентификаторы iOS сохранены в исходном пространстве имён; имя владельца по ним не угадывается. Наличие записи само по себе не доказывает удаление.");
            if (message.record_kind == "tl_message"||message.record_kind=="tl_message_caption") details.AppendLine("\r\nЗапись Telegram Android: поддерживаемая структура TL, конструктор " + Known(message.native_constructor, null, "неизвестен") + ". Имена чата и автора показываются только при наличии в источнике.");
            if(CacheRecord(message.record_kind)){
                details.AppendLine("\r\nМедиакэш Telegram: сохранившаяся подпись и ссылка на фотографию. Байты фотографии из этой записи не извлечены. Факт удаления сообщения не установлен.");
                if(message.evidence_kind=="previous")details.AppendLine("Подпись найдена в предыдущем проверенном снимке кэша; это не доказывает удаления переписки.");
            }
            if(!String.IsNullOrEmpty(message.native_tl_body_sha256))details.AppendLine("SHA256 TL-записи: "+message.native_tl_body_sha256);
            if(!String.IsNullOrEmpty(message.native_postbox_value_sha256))details.AppendLine("SHA256 Postbox-записи: "+message.native_postbox_value_sha256);
            if(message.sqlite_stored_mid!=null)details.AppendLine("Ключ записи в SQLite: "+Known(null,message.sqlite_stored_mid,"неизвестен")+". ID самого сообщения показан отдельно.");
            if(!String.IsNullOrEmpty(message.rollback_journal_sha256)){
                details.AppendLine(message.rollback_proof=="all_pages_from_validated_rollback_journal"
                    ? "\r\nСнимок из сохранившегося журнала SQLite: все исходные страницы присутствуют, связи записи проверены внутри снимка."
                    : message.rollback_proof=="archive_text_from_rollback_snapshot"
                    ? "\r\nТекст из локального архива в снимке SQLite. Принадлежность записи Telegram и связи чата не подтверждены."
                    : "\r\nФрагмент из сохранившегося журнала SQLite. Чат, автор и дата не установлены.");
                details.AppendLine("Журнал не подтверждает удаление или текущее состояние переписки. Контрольная сумма проверяет только часть байтов и не удостоверяет подлинность текста.");
                details.AppendLine("SHA256 журнала: "+message.rollback_journal_sha256);
                if(!String.IsNullOrEmpty(message.rollback_snapshot_sha256))details.AppendLine("SHA256 снимка: "+message.rollback_snapshot_sha256);
                if(message.rollback_payload_chain_verified==true)details.AppendLine("Текст собран из цепочки сохранившихся страниц журнала; отсутствующие страницы не подставлялись из текущей базы.");
                if(!String.IsNullOrEmpty(message.rollback_tail_reason))details.AppendLine("Журнал прочитан частично: "+message.rollback_tail_reason);
                if(!String.IsNullOrEmpty(message.rollback_page_map))details.AppendLine("Карта исходных байтов: "+message.rollback_page_map);
            }
            if (message.media_kind == "photo") details.AppendLine("\r\nВ записи есть фотография. Вложения включают только найденные локальные байты; наличие подписи не доказывает сохранность оригинального фото.");
            if (message.media_kind == "document" && message.media_status == "document_reference_only") details.AppendLine("\r\nСохранилась запись о вложении. Сам файл из этой записи не извлечён; его тип, имя и наличие локальных байтов не установлены. ID вложения: " + Known(message.media_id, null, "неизвестен") + ".");
            if (message.wal_proof == "all_pages_from_validated_wal") {
                details.AppendLine("\r\n"+(message.wal_snapshot_latest_known_commit==true?"Последний полностью проверенный коммит WAL":"Предыдущий зафиксированный снимок SQLite")+": кадр " + Known(null, message.wal_commit_frame, "неизвестен") + ". Все страницы снимка получены из проверенного журнала. Факт удаления сообщения не установлен.");
                details.AppendLine("SHA256 журнала: " + Known(message.wal_sha256, null, "неизвестен") + "\r\nSHA256 снимка: " + Known(message.wal_snapshot_sha256, null, "неизвестен"));
            }
            var uncertainWal=UnconfirmedWalOrigin(message);
            if(uncertainWal!=null){object prefix,reason;uncertainWal.TryGetValue("wal_validated_prefix_bytes",out prefix);uncertainWal.TryGetValue("wal_tail_reason",out reason);
                details.AppendLine((message.wal_current_state_confirmed==false?"":"Для одного из источников: ")+"Текущее состояние переписки не подтверждено. Хвост WAL повреждён или неполон; проверено байтов: "+Known(null,prefix,"неизвестно")+". Причина: "+Known(null,reason,"неизвестна"));}
            if(message.sqlite_overflow_chain_verified==true){
                details.AppendLine("\r\nЗапись SQLite собрана из сохранившейся цепочки свободных страниц. Диапазонов: "+(message.sqlite_payload_ranges==null?"неизвестно":message.sqlite_payload_ranges.Length.ToString(CultureInfo.InvariantCulture))+", байтов: "+Known(null,message.sqlite_payload_length,"неизвестно")+". SHA256 найденных байтов: "+Known(message.sqlite_payload_sha256,null,"неизвестен"));
                details.AppendLine("Цепочка и структура проверены. Это не подтверждает первоначальное содержание сообщения; полная карта исходных байтов сохранена в JSON архива.");
            }
            if(message.recovery_status=="deleted_supported_by_evidence")details.AppendLine("\r\nСтруктурная запись в свободной области страницы Telegram: отсутствует в текущей таблице. Ручное удаление пользователем не доказано. "+message.deletion_interpretation);
            if(message.residual_sources!=null)foreach(var origin in message.residual_sources){object at,page,kind,field;origin.TryGetValue("physical_byte_offset",out at);origin.TryGetValue("sqlite_page",out page);origin.TryGetValue("physical_source",out kind);origin.TryGetValue("text_field",out field);details.AppendLine("\r\nТакже сохранился остаток: "+kind+", страница "+page+", позиция "+at+". Факт ручного удаления не установлен.");if(field!=null)details.AppendLine("Поле текста остатка: "+TextFieldLabel(field as string));}
            if(message.sqlite_page!=null)details.AppendLine("\r\nSQLite: страница "+message.sqlite_page+", область "+message.sqlite_region+", позиция "+message.physical_byte_offset+", источник "+message.physical_source+(message.physical_source=="rollback_journal"?"":"; WAL frame "+message.wal_frame)+". "+message.proof);
            if (message.evidence_kind == "fragment") details.AppendLine("\r\nТекстовый фрагмент: принадлежность переписке и автору может быть неизвестна.");
            if (message.record_kind == "memory_fragment") details.AppendLine("\r\nФрагмент файла, Telegram не подтверждён. Позиция в файле: " + Convert.ToString(message.byte_offset) + " байт; кодировка: " + message.encoding + ". Дата, автор и факт удаления не установлены.");
            if(message.record_kind=="android_heap_message"){
                details.AppendLine("\r\nСвязанный объект сообщения в предоставленном дампе Java/Android. Принадлежность аккаунту и факт удаления не подтверждены.");
                details.AppendLine("Класс: "+message.heap_class+"; идентификатор объекта дампа: "+message.heap_object_id+"; позиция: "+message.physical_byte_offset+". Это идентификатор в файле, а не доступ к памяти устройства.");
                details.AppendLine("Поля объекта (предположительные): сообщение "+Known(null,message.candidate_message_id,"неизвестно")+", получатель "+Known(null,message.candidate_peer,"неизвестен")+", автор "+Known(null,message.candidate_sender,"неизвестен")+", дата Unix "+Known(null,message.candidate_date,"неизвестна")+". SHA256 записи: "+message.heap_record_sha256);
            }
            if (message.text_truncated) details.AppendLine("\r\nПоказан фрагмент: символы "+message.text_offset+"–"+(message.text_end>0?message.text_end:Math.Min(message.text_length,65536))+" из "+message.text_length+". Полная запись остаётся в архиве; открой «Полный текст» для чтения частями.");
            if (current != null && current.warnings != null && current.warnings.Length > 0) details.AppendLine("\r\nПри чтении архива часть некорректных записей пропущена или использован резервный JSONL.");
            if (message.sources != null) foreach (var origin in message.sources) {
                object file,record,kind,digest,walDb,field;origin.TryGetValue("source_file",out file);origin.TryGetValue("source_record",out record);origin.TryGetValue("record_kind",out kind);origin.TryGetValue("native_tl_body_sha256",out digest);origin.TryGetValue("wal_db_sha256",out walDb);origin.TryGetValue("text_field",out field);
                details.AppendLine("\r\nТакже: "+Known(null,file,"источник неизвестен")+" · "+Known(null,record,"запись неизвестна"));
                if(CacheRecord(kind as string))details.AppendLine("Дополнительный источник — медиакэш Telegram. Факт удаления сообщения по кэшу не установлен; ссылка на фото не означает, что его байты извлечены.");
                if(field!=null)details.AppendLine("Поле текста источника: "+TextFieldLabel(field as string));
                if(digest!=null)details.AppendLine("SHA256 TL-записи источника: "+Known(null,digest,"неизвестен"));
                if(walDb!=null)details.AppendLine("SHA256 базы источника WAL: "+Known(null,walDb,"неизвестен"));
            }
            const int maximumDetails=24576;
            if(details.Length>maximumDetails){details.Length=maximumDetails;if(Char.IsHighSurrogate(details[details.Length-1]))details.Length--;details.Append("\r\n… Полное происхождение сохранено в JSON архива.");}
            provenance.Text = details.ToString();
            if (message.attachments != null) foreach (string item in message.attachments) if (Regex.IsMatch(item ?? "", "^media/[a-f0-9]{64}\\.[a-z0-9]{1,12}$")) attachments.Items.Add(new AttachmentChoice { Path = item, Number = attachments.Items.Count + 1 });
            if (attachments.Items.Count > 0) { attachments.SelectedIndex = 0; openAttachment.Enabled = true; }
        }
        void OpenFullText()
        {
            var message=grid.SelectedRows.Count==0?null:grid.SelectedRows[0].Tag as ArchiveMessage;
            if(message==null||String.IsNullOrEmpty(message.archive_record_key))return;
            using(var viewer=new ArchiveMessageTextForm(archive.Text,message))viewer.ShowDialog(this);
        }
        sealed class AttachmentChoice { public string Path; public int Number; public override string ToString() { return "Вложение " + Number + " · " + System.IO.Path.GetExtension(Path).TrimStart('.').ToUpperInvariant(); } }
        async void OpenAttachment()
        {
            if (current == null || attachments.SelectedItem == null) return;
            string root = current.archive, relative = ((AttachmentChoice)attachments.SelectedItem).Path; openAttachment.Enabled = false;
            try { string path = await Task.Run(() => ArchiveSearchService.VerifiedAttachment(root, relative)); if (!IsDisposed) Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
            catch { if (!IsDisposed) MessageBox.Show(this, "Вложение недоступно, изменилось или его тип нельзя открыть из архива.", "Вложение", MessageBoxButtons.OK, MessageBoxIcon.Information); }
            finally { if (!IsDisposed) openAttachment.Enabled = attachments.Items.Count > 0; }
        }
    }
}
