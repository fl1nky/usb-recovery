using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ArchiveTextPortableTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    public static int Main(string[] args)
    {
        try{
            string root=Path.Combine(Path.GetFullPath(args[0]),".build","archive-text-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
            string text=new string('x',100000)+" 🥧 искомый рецепт прабабушки\r\n"+new string('y',50000)+" 🧬 конец";
            var serializer=new JavaScriptSerializer{MaxJsonLength=4*1024*1024};
            string source=Path.Combine(root,"messages.jsonl");File.WriteAllText(source,serializer.Serialize(new{app="Telegram",text=text,evidence_kind="backup",chat_id=77,message_id=3,sqlite_stored_mid=Int64.MaxValue,source_file="owned fixture",source_record="row3"})+"\n",new UTF8Encoding(false));
            string before=Hash(source);var stamp=File.GetLastWriteTimeUtc(source);
            foreach(bool regex in new[]{false,true}){
                var result=ArchiveSearchService.Search(root,"Telegram",regex?"рецепт.*прабабушки":"прабабушки","",0,CancellationToken.None,regex);
                Check(result.status=="complete"&&result.total==1,"actual frozen helper finds later literal/regex match");var message=result.records.Single();
                Check(message.text.Contains("прабабушки")&&message.text_offset>0&&message.text_truncated,"actual matching context is visible with truthful offset");
                Check(message.archive_record_key.StartsWith("jsonl:"),"fingerprint-bound locator survives DTO");
                Check(Convert.ToInt64(message.sqlite_stored_mid)==Int64.MaxValue,"signed64 SQLite identity reaches C# without rounding");
                var all=new StringBuilder();long offset=0;while(true){
                    var page=ArchiveSearchService.ReadPage(root,message.archive_record_key,offset,CancellationToken.None);
                    Check(page.status=="complete"&&page.text_offset==offset&&page.next_offset>=offset,"actual page protocol is coherent");all.Append(page.text);offset=page.next_offset;
                    if(page.eof){Check(page.next_offset==page.text_length,"complete Unicode length reached");break;}
                }
                Check(all.ToString()==text,"all Unicode pages reconstruct the exact full archived text");
                Check(Hash(source)==before&&File.GetLastWriteTimeUtc(source)==stamp,"search/read pages never rewrite the source");
            }
            string indexed=Path.Combine(root,"indexed");var imported=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="telegram_analyze",destination=indexed,options=new{roots=new[]{source},scan_fragments=false}},CancellationToken.None,null);
            Check(imported.Status!="error"&&File.Exists(Path.Combine(indexed,"chat-index.sqlite")),"actual helper creates the canonical SQLite search index");
            string index=Path.Combine(indexed,"chat-index.sqlite"),indexBefore=Hash(index),jsonl=Path.Combine(indexed,"messages.jsonl"),jsonlBefore=Hash(jsonl);
            var indexedMessage=ArchiveSearchService.Search(indexed,"Telegram","прабабушки","",0,CancellationToken.None).records.Single();
            Check(indexedMessage.archive_record_key.StartsWith("sqlite:")&&indexedMessage.text.Contains("прабабушки"),"actual SQLite context and locator reach the client");
            var indexedText=new StringBuilder();long indexedOffset=0;while(true){var page=ArchiveSearchService.ReadPage(indexed,indexedMessage.archive_record_key,indexedOffset,CancellationToken.None);indexedText.Append(page.text);indexedOffset=page.next_offset;if(page.eof)break;}
            Check(indexedText.ToString()==text,"actual SQLite pages reconstruct exact full Unicode text");
            Check(Hash(index)==indexBefore&&Hash(jsonl)==jsonlBefore&&Hash(source)==before&&File.GetLastWriteTimeUtc(source)==stamp,"SQLite and JSONL read paths keep every owned source unchanged");
            Check(!File.Exists(index+"-wal")&&!File.Exists(index+"-shm"),"read-only index pages do not create SQLite sidecars");
            var selected=ArchiveSearchService.Search(root,"Telegram","прабабушки","",0,CancellationToken.None).records.Single();
            string changed=File.ReadAllText(source,Encoding.UTF8).Replace("рецепт","Рецепт");File.WriteAllText(source,changed,new UTF8Encoding(false));File.SetLastWriteTimeUtc(source,stamp);
            var stale=ArchiveSearchService.ReadPage(root,selected.archive_record_key,0,CancellationToken.None);
            Check(stale.status=="error"&&stale.code=="RECORD_CHANGED","same-size restored-mtime record edit cannot reuse a stale locator");
            Console.WriteLine("PASS ArchiveTextPortable: "+checks+" checks; actual frozen helper, JSONL/SQLite literal/regex contexts, full Unicode pages, stale fingerprint rejection and immutable owned archive.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
