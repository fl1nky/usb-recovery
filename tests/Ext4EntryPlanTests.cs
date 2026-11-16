using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Storage controls use supplied synthetic metadata, not a validated filesystem
// allocation map. The large plan exceeds the root checkpoint's 16 MiB limit.
public static class Ext4EntryPlanTests
{
    static int checks;
    static readonly BindingFlags Private=BindingFlags.NonPublic|BindingFlags.Static;
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static void Set(object value,string name,object data){value.GetType().GetField(name).SetValue(value,data);}
    static string Hash(string file){return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{});}
    static string Identity(Ext4Recovery.Entry entry){return (string)typeof(Ext4Recovery).GetMethod("Ext4EntryIdentity",Private).Invoke(null,new object[]{entry,CancellationToken.None});}
    static Ext4Recovery.Entry Entry()
    {
        var entry=new Ext4Recovery.Entry{Inode=13,Generation=7,DeclaredSize=1100,Status="not_recovered",VolumeOffset=4096};
        for(int i=0;i<1100;i++)entry.Extents.Add(new Ext4Recovery.Extent{ImageOffset=8192+i,LogicalOffset=i,Length=1});
        string path="/"+new string('x',9000)+"/";
        for(int i=0;i<2000;i++)entry.Names.Add(new Ext4Recovery.NameLink{Name="рецепт-"+i,DirectoryPath=path,TargetInode=13,DirectoryInode=2,
            EntryOffset=16384+i,JournalBlockOffset=i%2==0?(long?)32768:null,TargetBlockOffset=65536,JournalTransactionSequence=7});
        return entry;
    }
    static RecoveryMethodCheckpoint Anchor(string root)
    {string file=Path.Combine(root,"anchor.json");return File.Exists(file)?Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(file,Encoding.UTF8)):null;}
    static void SaveAnchor(string root,RecoveryMethodCheckpoint value)
    {
        string file=Path.Combine(root,"anchor.json"),temp=file+"."+Guid.NewGuid().ToString("N")+".partial";bool own=false;
        try{byte[] bytes=Encoding.UTF8.GetBytes(Json.Serialize(value));using(var output=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){own=true;output.Write(bytes,0,bytes.Length);output.Flush(true);}
            if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);}
        finally{if(own&&File.Exists(temp))File.Delete(temp);}
    }
    static string Run(string root,Ext4Recovery.Entry entry,CancellationToken token,Action<string> progress)
    {
        string image=Path.Combine(root,"owned.dd");if(!File.Exists(image))File.WriteAllText(image,"owned metadata plan storage control");
        string sha=Hash(image);using(var input=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read)){
            object c=Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            Set(c,"Input",input);Set(c,"Root",Path.Combine(root,"ext4"));Set(c,"Cancel",token);Set(c,"Limits",new Ext4Recovery.Limits());Set(c,"Report",new Ext4Recovery.Report());
            object context=Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
            Set(context,"Directory",root);Set(context,"Method","ext4");Set(context,"SourceSha256",sha);Set(context,"Settings","owned-entry-plan-v1");Set(context,"Resume",Anchor(root));
            Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a=>SaveAnchor(root,a)));
            string manifest;
            try{manifest=(string)typeof(Ext4Recovery).GetMethod("StoreEntryPlan",Private).Invoke(null,new[]{c,entry,context,progress});}
            catch(TargetInvocationException error){throw error.InnerException;}
            var restored=(Ext4Recovery.Entry)typeof(Ext4Recovery).GetMethod("ReadEntryPlan",Private).Invoke(null,new[]{c,context,manifest});
            Check(Identity(entry)==Identity(restored),"all scalar fields, extents, names and nullable provenance survive paged storage");
            Check(Hash(image)==sha,"entry storage leaves source bytes unchanged");return manifest;
        }
    }
    public static int Main(string[] args)
    {
        try{
            string root=Path.Combine(Path.GetFullPath(args[0]),".build","ext4-entry-plan-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
            var entry=Entry();bool stopped=false;
            using(var cancel=new CancellationTokenSource()){
                try{Run(root,entry,cancel.Token,m=>{if(m.Contains("names 128"))cancel.Cancel();});}catch(OperationCanceledException){stopped=true;}
            }
            Check(stopped&&Anchor(root)!=null,"large plan stops inside persisted name pages");
            string manifest=Run(root,entry,CancellationToken.None,null);
            Check(new FileInfo(Anchor(root).Path).Length<1024*1024,"large entry never becomes a giant root checkpoint");
            var pages=Directory.GetFiles(Path.Combine(root,"ext4.state"),"page-*.json",SearchOption.AllDirectories);
            Check(pages.Length>10&&pages.All(x=>new FileInfo(x).Length<=256*1024),"metadata is split into genuinely bounded immutable pages");
            Check(new FileInfo(Path.Combine(root,"ext4.state","export-blobs","blob-"+manifest+".json")).Length<1024*1024,"manifest contains only bounded header and page heads");
            Check(Run(root,entry,CancellationToken.None,m=>{throw new Exception("completed plan restarted");})==manifest,"completed entry plan is reused");
            string parent=Hash(Path.Combine(root,"anchor.json"));entry.Names[0].Name+=" changed";bool rejected=false;
            try{Run(root,entry,CancellationToken.None,null);}catch(IOException){rejected=true;}
            Check(rejected&&Hash(Path.Combine(root,"anchor.json"))==parent,"changed metadata cannot resume an earlier plan");
            Console.WriteLine("PASS Ext4EntryPlan: "+checks+" checks; supplied metadata over 16 MiB, no filesystem recovery/device claim");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
