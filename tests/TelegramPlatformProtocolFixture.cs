using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

// Controlled stdin transport fixture only, never a native-format recovery oracle.
public static class TelegramPlatformProtocolFixture
{
    public static int Main()
    {
        try {
            var json=new JavaScriptSerializer();
            string input;using(var reader=new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false)))input=reader.ReadToEnd();
            var request=json.Deserialize<Dictionary<string,object>>(input);
            var secrets=request["secrets"] as Dictionary<string,object>;
            var options=request["options"] as Dictionary<string,object>;
            bool knownEmpty=Convert.ToString(options["fragment_query"])=="known-empty";
            string expected=knownEmpty?"":"SYNTHETIC_DESKTOP_PASSCODE_CANARY";
            if(Convert.ToString(request["operation"])!="telegram_analyze"||secrets==null||
                !secrets.ContainsKey("telegram_desktop_passcode")||Convert.ToString(secrets["telegram_desktop_passcode"])!=expected||
                Environment.CommandLine.Contains("SYNTHETIC_DESKTOP_PASSCODE_CANARY"))return 2;
            string output=Convert.ToString(request["destination"]);Directory.CreateDirectory(output);
            File.WriteAllText(Path.Combine(output,"messages.jsonl"),"",new UTF8Encoding(false));
            Console.Error.WriteLine(expected);
            Console.WriteLine(json.Serialize(new{type="progress",phase="telegram_read",message=expected}));
            Console.WriteLine(json.Serialize(new{type="result",status="complete",code="LOCAL_DRAFTS_OR_SCHEDULED_AVAILABLE",
                archive=output,messages=5,history_messages=0,draft_records=2,scheduled_records=3,native_records=5,
                readable_sources=2,encrypted_sources=1,warnings=new string[0]}));
            return 0;
        } catch { return 3; }
    }
}
