using System;
using System.IO;
using System.Threading;
using UsbRecovery;

public static class ArchiveTextProtocolAuditTests
{
    static int checks,failures;
    static void Check(bool valid,string label){checks++;if(!valid){failures++;Console.WriteLine("FAIL: "+label);}else Console.WriteLine("PASS: "+label);}
    static void Reject(Action action,string label){bool rejected=false;try{action();}catch(IOException){rejected=true;}Check(rejected,label);}
    public static int Main()
    {
        try{
            string key="jsonl:0:"+new string('a',64);
            var valid=ArchiveSearchService.ReadPage("valid",key,0,CancellationToken.None);
            Check(valid.text=="safe"&&valid.eof&&valid.next_offset==4,"valid page remains readable");
            Reject(()=>ArchiveSearchService.ReadPage("oversized",key,0,CancellationToken.None),"100000-scalar page exceeds requested 65536 limit");
            Reject(()=>ArchiveSearchService.ReadPage("partial",key,0,CancellationToken.None),"partial status cannot publish a full-text page");
            Check(ArchiveSearchService.ReadPage("controlled-error",key,0,CancellationToken.None).code=="RECORD_CHANGED","controlled helper errors remain visible");
            Check(ArchiveSearchService.Search("valid","Telegram","","",0,CancellationToken.None).records[0].text=="safe","short legacy-shaped record remains readable");
            var context=ArchiveSearchService.Search("long-valid","Telegram","","",0,CancellationToken.None).records[0];
            Check(context.text_offset==60000&&context.match_offset==60000,"valid long-message coordinates remain readable");
            var longRegex=ArchiveSearchService.Search("long-regex","Telegram",".*","",0,CancellationToken.None,true).records[0];
            Check(longRegex.match_end>longRegex.text_end,"valid regex match may continue beyond visible context");
            var eofRegex=ArchiveSearchService.Search("eof-regex","Telegram","$","",0,CancellationToken.None,true).records[0];
            Check(eofRegex.match_offset==eofRegex.text_length&&eofRegex.match_end==eofRegex.text_length,"zero-width regex at EOF remains valid");
            Check(ArchiveSearchService.Search("astral","Telegram","","",0,CancellationToken.None).records[0].text_end==60005,"snippet extent counts astral scalar once");
            foreach(string invalid in new[]{"null-record","null-text","bad-context","bad-match"})
                Reject(()=>ArchiveSearchService.Search(invalid,"Telegram","","",0,CancellationToken.None),"invalid search record rejected: "+invalid);
            Console.WriteLine("Archive protocol independent audit: "+checks+" checks, "+failures+" failures; no UI shown.");
            return failures==0?0:1;
        }catch(Exception failure){Console.WriteLine(failure);return 2;}
    }
}
