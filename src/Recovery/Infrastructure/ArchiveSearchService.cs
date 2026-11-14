using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
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

}
