using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class HelperCheckpointProtocolTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    public static int Main(string[] args)
    {
        if(args.Length==0){
            Console.InputEncoding=Encoding.UTF8;Console.OutputEncoding=new UTF8Encoding(false);
            var json=new JavaScriptSerializer();var request=json.Deserialize<System.Collections.Generic.Dictionary<string,object>>(Console.ReadLine());
            Console.Error.WriteLine("PRIVATE_DIAGNOSTIC_MUST_NOT_APPEAR");
            Console.WriteLine(json.Serialize(new{type="progress",phase="photo_checkpoint",checkpoint_path=Convert.ToString(request["path"]),checkpoint_sha256=new string('a',64),checkpoint_sequence=7,completed=0,total=0}));
            Console.WriteLine(json.Serialize(new{type="progress",phase="photo_index",completed=33554432L,total=73400320L}));
            Console.WriteLine(json.Serialize(new{type="result",status="error",code=Convert.ToString(request["code"])}));return 0;
        }
        try{
            string executable=Assembly.GetExecutingAssembly().Location,path=Path.Combine(Path.GetFullPath(args[0]),".build","own checkpoint-000000000007.json");
            foreach(string code in new[]{"PHOTO_CHECKPOINT_HASH_MISMATCH","PHOTO_CHECKPOINT_BINDING_MISMATCH","PHOTO_CHECKPOINT_OUTPUT_CHANGED","IO_ERROR","PHOTO_CHECKPOINT_secret/path","PHOTO_CHECKPOINT_"+new string('A',45)}){
                int callbacks=0;var result=HelperClient.Run(executable,new{protocol=1,operation="owned_protocol_probe",path=path,code=code},CancellationToken.None,s=>{},update=>{
                    callbacks++;if(update.Phase=="photo_checkpoint")Check(update.CheckpointPath==path&&update.CheckpointSha256==new string('a',64)&&update.CheckpointSequence==7,"actual child forwards complete immutable checkpoint envelope");
                    else Check(update.Phase=="photo_index"&&update.Completed==33554432&&update.Total==73400320&&String.IsNullOrEmpty(update.CheckpointPath),"ordinary byte progress remains distinct from checkpoint events");
                });
                bool valid=code=="IO_ERROR"||code.EndsWith("MISMATCH",StringComparison.Ordinal)||code.EndsWith("CHANGED",StringComparison.Ordinal);
                Check(result.Status=="error"&&result.Code==(valid?code:"HELPER_FAILED")&&callbacks==2,"only bounded own codes survive the helper boundary");
                Check(!FragmentedPhotoRecovery.ErrorText(result.Code).Contains("PRIVATE")&&!FragmentedPhotoRecovery.ErrorText(result.Code).Contains(path),"user errors contain neither raw diagnostics nor source paths");
            }
            Check(!File.Exists(path),"protocol probing never writes an input or checkpoint file");
            Console.WriteLine("PASS HelperCheckpointProtocol: "+checks+" checks; actual isolated child NDJSON, checkpoint metadata/byte progress, bounded own errors and discarded raw diagnostics. No user data or devices.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
