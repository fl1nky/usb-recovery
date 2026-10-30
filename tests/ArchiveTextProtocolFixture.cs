using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

public static class ArchiveTextProtocolFixture
{
    public static int Main()
    {
        Console.InputEncoding=Encoding.UTF8;Console.OutputEncoding=new UTF8Encoding(false);
        var json=new JavaScriptSerializer{MaxJsonLength=1024*1024};var request=json.Deserialize<Dictionary<string,object>>(Console.ReadLine());
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
}
