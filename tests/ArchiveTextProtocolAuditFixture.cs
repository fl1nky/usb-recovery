using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

// Synthetic worker for independent protocol validation; never reads an archive.
public static class ArchiveTextProtocolAuditFixture
{
    public static int Main()
    {
        Console.InputEncoding=Encoding.UTF8;Console.OutputEncoding=new UTF8Encoding(false);
        var json=new JavaScriptSerializer{MaxJsonLength=1024*1024};
        var request=json.Deserialize<Dictionary<string,object>>(Console.ReadLine());
        string mode=Convert.ToString(request["archive"]),operation=Convert.ToString(request["operation"]);
        var response=new Dictionary<string,object>{{"protocol",1},{"type","result"},{"status","complete"},{"code","OK"},{"archive",mode}};
        if(operation=="message_page"){
            string text=mode=="oversized"?new string('a',100000):"safe";
            response["record_key"]=request["record_key"];response["text"]=text;response["text_offset"]=0;
            response["next_offset"]=text.Length;response["text_length"]=text.Length;response["limit"]=65536;response["eof"]=true;
            if(mode=="partial")response["status"]="partial";
            if(mode=="controlled-error"){response["status"]="error";response["code"]="RECORD_CHANGED";}
        }else{
            var record=new Dictionary<string,object>{{"app","Telegram"},{"evidence_kind","export"},{"text","safe"}};
            if(mode=="null-text")record["text"]=null;
            if(mode=="long-valid"||mode=="bad-context"||mode=="bad-match"||mode=="long-regex"||mode=="eof-regex"||mode=="astral"){
                record["text_truncated"]=true;record["text_length"]=70000;record["text_offset"]=60000;record["text_end"]=60004;
                record["match_offset"]=60000;record["match_end"]=60004;
                record["archive_record_key"]="jsonl:0:"+new string('a',64);
                if(mode=="bad-context")record["text_offset"]=-2;
                if(mode=="bad-match")record["match_end"]=70001;
                if(mode=="long-regex")record["match_end"]=69000;
                if(mode=="eof-regex"){record["text_offset"]=69996;record["text_end"]=70000;record["match_offset"]=70000;record["match_end"]=70000;}
                if(mode=="astral"){record["text"]=Char.ConvertFromUtf32(0x1f967)+"safe";record["text_end"]=60005;record["match_end"]=60005;}
            }
            response["total"]=1;response["offset"]=0;response["limit"]=100;
            response["records"]=new object[]{mode=="null-record"?null:record};
        }
        Console.WriteLine(json.Serialize(response));return mode=="controlled-error"?2:0;
    }
}
