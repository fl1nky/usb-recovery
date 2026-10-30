using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class AndroidHeapPortableTests
{
    public sealed class Expected { public int id, date; public string text, peer, sender; }
    public sealed class Manifest { public int schema; public string path, sha256, scope, java_sha256, javac_sha256; public List<Expected> expected; }
    static int checks;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return Hex(sha.ComputeHash(input));}
    static string Hex(byte[] bytes){return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
    static string Hash(byte[] bytes){using(var sha=SHA256.Create())return Hex(sha.ComputeHash(bytes));}
    static byte[] Range(string path,long offset,long count)
    {
        using(var source=File.OpenRead(path)){
            Check(offset>=0&&count>0&&count<=262144&&offset<=source.Length-count,"Physical source range bounded by supplied heap");
            var bytes=new byte[(int)count];source.Position=offset;int position=0;
            while(position<bytes.Length){int read=source.Read(bytes,position,bytes.Length-position);if(read==0)throw new EndOfStreamException();position+=read;}
            return bytes;
        }
    }
    static ArchiveSearchResult Search(string archive,string query,string category,bool regex=false)
    {
        var result=ArchiveSearchService.Search(archive,"Telegram",query,category,0,CancellationToken.None,regex);
        Check(result.status!="error"&&result.records!=null,"Actual frozen search returned records through C# DTO");return result;
    }
    static void Validate(ArchiveMessage row,Expected expected,string source,string sha)
    {
        Check(row.record_kind=="android_heap_message"&&row.evidence_kind=="fragment","Heap graph stays a structured fragment");
        Check(row.completeness=="structured_heap_candidate"&&row.recovery_status=="unattributed_structured_fragment","Graph is not promoted to confirmed history");
        Check(row.application_confirmed==false&&row.deleted==null,"Application ownership and deletion remain unconfirmed");
        Check(row.chat_id==null&&row.sender_id==null&&row.message_id==null&&row.timestamp==null,"Candidate IDs and date do not fill confirmed fields");
        Check(row.text==expected.text&&Convert.ToInt64(row.candidate_message_id)==expected.id&&Convert.ToInt64(row.candidate_date)==expected.date,"Text and tentative fields survive actual archive search");
        Check(Convert.ToString(row.candidate_peer)==expected.peer&&Convert.ToString(row.candidate_sender)==expected.sender,"Tentative peer/sender retained separately");
        Check(row.heap_class=="org.telegram.tgnet.TLRPC$TL_message"&&row.proof=="hprof_class_and_object_references","Recognized class and proof retained");
        Check(!String.IsNullOrEmpty(row.heap_object_id)&&row.source_record=="hprof-object:"+row.heap_object_id,"Record links to supplied heap object identifier");
        Check(row.heap_version=="JAVA PROFILE 1.0.2"||row.heap_version=="JAVA PROFILE 1.0.3"||row.heap_version=="JAVA PROFILE 1.0.1","Actual HPROF version retained");
        Check(Convert.ToInt64(row.heap_identifier_bytes)==4||Convert.ToInt64(row.heap_identifier_bytes)==8,"Identifier width retained");
        Check(Convert.ToInt64(row.heap_snapshot_ms)>0&&row.offset_kind=="hprof_instance_data","Snapshot and physical offset kind retained");
        Check(row.source_sha256==sha&&row.snapshot_id==sha&&row.source_file==source&&!String.IsNullOrEmpty(row.source_id),"Acquisition provenance links to immutable supplied heap");
        byte[] record=Range(source,Convert.ToInt64(row.physical_byte_offset),Convert.ToInt64(row.heap_record_length));
        Check(Hash(record)==row.heap_record_sha256,"Record SHA256 matches exact physical instance bytes");
        byte[] text=Range(source,Convert.ToInt64(row.byte_offset),Convert.ToInt64(row.byte_length));
        Encoding encoding=row.encoding=="latin-1"?Encoding.GetEncoding(28591):row.encoding=="utf-16-be"?Encoding.BigEndianUnicode:row.encoding=="utf-16-le"?Encoding.Unicode:null;
        Check(encoding!=null&&encoding.GetString(text)==expected.text,"Character array bytes reproduce displayed Unicode text");
        Check(Hash(Encoding.UTF8.GetBytes(row.text))==row.heap_text_sha256,"Text SHA256 retained without character loss");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),fixtures=Path.Combine(project,".build","telegram-heap-portable-fixtures");
            var json=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};var manifest=json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json"),Encoding.UTF8));
            Check(manifest.schema==1&&manifest.expected.Count==2&&!String.IsNullOrWhiteSpace(manifest.scope),"Owned real-JVM fixture manifest available");
            Check(manifest.java_sha256.Length==64&&manifest.javac_sha256.Length==64,"Fixture binds independent JVM and compiler binaries");
            string original=RecoveryCatalog.SafeFile(fixtures,manifest.path);Check(Hash(original)==manifest.sha256,"Original independent heap matches fixture hash");
            string work=Path.Combine(project,".build","android-heap-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            string source=Path.Combine(work,"provided.hidden"),output=Path.Combine(work,"archive");File.Copy(original,source);
            Check(File.Exists(HelperClient.Executable),"Actual frozen helper available");
            var result=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="telegram_analyze",destination=output,options=new{roots=new[]{source},scan_fragments=false}},CancellationToken.None,s=>{});
            Check(result.Status=="partial"&&Directory.Exists(output)&&!File.Exists(Path.Combine(output,"job.incomplete")),"Hidden-extension heap publishes complete files with explicit partial-evidence status");
            Check(result.Messages==2&&result.StructuredFragmentRecords==2&&result.FragmentRecords==2,"Frozen helper finds exactly two structured heap candidates");
            Check(result.HistoryMessages==0&&result.DeletedSupportedRecords==0&&result.NativeRecords==0,"Heap candidates do not claim recovered deleted chat history");
            string messages=Path.Combine(output,"messages.jsonl"),index=Path.Combine(output,"chat-index.sqlite"),html=Path.Combine(output,"Переписки.html");
            Check(File.Exists(messages)&&File.Exists(index)&&File.Exists(html),"JSONL, local search index and HTML archive published");
            Check(!File.ReadAllText(messages,Encoding.UTF8).Contains("PRIVATE_CANARY")&&!File.ReadAllText(html,Encoding.UTF8).Contains("PRIVATE_CANARY"),"Unrelated object's private canary is not published as message text");
            var unchanged=new Dictionary<string,string>();foreach(string path in new[]{messages,index,html,Path.Combine(output,"sources.json")})unchanged[path]=Hash(path);
            var rows=Search(output,"","fragment");Check(rows.total==2&&rows.records.Count==2,"Fragment category returns both candidates");
            foreach(var expected in manifest.expected){var row=rows.records.Single(x=>Convert.ToInt64(x.candidate_message_id)==expected.id);Validate(row,expected,source,manifest.sha256);}
            Check(Search(output,"recipe","fragment").total==1,"Literal ASCII keyword search over frozen archive");
            Check(Search(output,"рецепт","fragment").total==1,"Literal Unicode keyword search over frozen archive");
            Check(Search(output,"(?s)recipe.*second line","fragment",true).total==1,"Regex keyword search across a multiline heap message");
            Check(Search(output,"рецепт\\s+.","fragment",true).total==1,"Regex Unicode search retains emoji candidate");
            Check(Search(output,"recipe.*second line","fragment").total==0,"Literal search does not silently interpret a regular expression");
            Check(Search(output,"","deleted").total==0&&Search(output,"","backup").total==0&&Search(output,"","previous").total==0,"Unknown deletion and snapshot relationships are not invented");
            Check(Search(output,"PRIVATE_CANARY","fragment").total==0,"Unrelated class is absent from keyword results");
            string saved=index+".audit-saved";File.Move(index,saved);
            try{var fallback=Search(output,"","fragment");Check(fallback.total==2,"Streaming JSONL search remains available without local index");foreach(var expected in manifest.expected)Validate(fallback.records.Single(x=>Convert.ToInt64(x.candidate_message_id)==expected.id),expected,source,manifest.sha256);}
            finally{File.Move(saved,index);}
            foreach(var pair in unchanged)Check(Hash(pair.Key)==pair.Value,"Read-only searching preserves archive bytes");
            Check(!File.Exists(index+"-wal")&&!File.Exists(index+"-shm"),"Read-only search creates no SQLite sidecars");
            Check(Hash(source)==manifest.sha256&&Hash(original)==manifest.sha256,"Acquisition and all searches preserve both original and supplied heap bytes");
            Console.WriteLine("PASS AndroidHeapPortable: "+checks+" checks; actual frozen helper and C# search, owned real JVM HPROF, tentative graph metadata, exact physical hashes, Unicode/literal/regex/JSONL queries and immutable source/archive. No Android hardware or Telegram application was tested.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
