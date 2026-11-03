using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

public static class ArchiveTextProtocolFixture
{
    public static int Main()
    {
        Console.InputEncoding=Encoding.UTF8;Console.OutputEncoding=new UTF8Encoding(false);
        var json=new JavaScriptSerializer{MaxJsonLength=1024*1024};var request=json.Deserialize<Dictionary<string,object>>(Console.ReadLine());
        if(Convert.ToString(request["operation"])=="search")return Search(request,json);
        string archive=Convert.ToString(request["archive"]),key=Convert.ToString(request["record_key"]);long offset=Convert.ToInt64(request["text_offset"]);
        if(archive.Contains("hang")){Thread.Sleep(20000);return 1;}
        if(archive.Contains("surrogate")){Console.WriteLine("{\"protocol\":1,\"type\":\"result\",\"status\":\"complete\",\"code\":\"OK\",\"record_key\":\""+key+"\",\"text\":\"\\ud800\",\"text_offset\":0,\"next_offset\":1,\"text_length\":1,\"limit\":65536,\"eof\":true}");return 0;}
        string text="start "+new string('x',70000)+Char.ConvertFromUtf32(0x1f967)+" needle\r\n"+new string('y',70000)+" end";
        var utf32=new UTF32Encoding(false,false,true);byte[] bytes=utf32.GetBytes(text);long length=bytes.Length/4,end=Math.Min(length,offset+65536);
        string page=utf32.GetString(bytes,checked((int)offset*4),checked((int)(end-offset)*4));
        if(archive.Contains("over-limit")){page=new string('z',100000);end=offset+100000;}
        bool changed=archive.Contains("changed");
        Console.WriteLine(json.Serialize(new{protocol=1,type="result",status=changed?"error":archive.Contains("partial-page")?"partial":"complete",code=changed?"RECORD_CHANGED":"OK",archive=archive,
            record_key=archive.Contains("wrong-key")?key+"x":key,text=page,text_offset=archive.Contains("wrong-offset")?offset+1:offset,
            next_offset=archive.Contains("wrong-length")?end+1:end,text_length=length,limit=65536,eof=end==length}));
        return changed?2:0;
    }
    static int Search(Dictionary<string,object> request,JavaScriptSerializer json)
    {
        string query=Convert.ToString(request["query"]),archive=Convert.ToString(request["archive"]);
        long offset=Convert.ToInt64(request["offset"]);int limit=Convert.ToInt32(request["limit"]);
        string log=Path.Combine(Path.GetDirectoryName(typeof(ArchiveTextProtocolFixture).Assembly.Location),"search-requests.jsonl");
        File.AppendAllText(log,json.Serialize(new{query=query,offset=offset,limit=limit,evidence=Convert.ToString(request["evidence"]),query_mode=Convert.ToString(request["query_mode"])})+"\n",new UTF8Encoding(false));
        if(query=="window-error"||offset<0||offset+limit>100000){Console.WriteLine(json.Serialize(new{protocol=1,type="result",status="error",code="QUERY_WINDOW_LIMIT",archive=archive}));return 2;}
        if(query=="generic-error"){Console.WriteLine(json.Serialize(new{protocol=1,type="result",status="error",code="ARCHIVE_NOT_FOUND",archive=archive}));return 2;}
        long total=query=="small"?3:query=="total99999"?99999:query=="total100000"?100000:query=="total100001"?100001:250000;
        var records=new List<object>();
        for(long index=offset;index<Math.Min(total,offset+limit);index++){
            string text="owned "+query+" page "+offset+" row "+index;
            records.Add(new{app="Telegram",text=text,chat_name="Тестовый чат",sender_name="Тестовый автор",evidence_kind="export",
                source_file="owned-search-fixture",source_record="record:"+index,source_sha256=new string('a',64),snapshot_id="owned-search",
                archive_record_key="jsonl:"+index+":"+new string('a',64),text_truncated=true,text_length=200000,text_offset=100,text_end=100+text.Length,
                match_offset=100,match_end=105,attachments=new string[0]});
        }
        Console.WriteLine(json.Serialize(new{protocol=1,type="result",status=query=="partial-many"?"partial":"complete",code="OK",archive=archive,
            total=total,offset=offset,limit=limit,warnings=new string[0],records=records}));
        return 0;
    }
}
