// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Exercise the actual shared publisher on owned regular files. No parser mocks.
public static class MappedContentCheckpointTests
{
    const int MiB = 1024 * 1024;
    static int checks;
    static string work, image, sourceHash, payloadHash;
    static readonly Assembly App = typeof(RecoverySession).Assembly;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static void Set(object owner, string name, object value) { owner.GetType().GetField(name).SetValue(owner,value); }
    static object New(string name) { return Activator.CreateInstance(App.GetType("UsbRecovery."+name,true),true); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{}); }
    static string Hex(byte[] bytes) { using (var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant(); }
    static string AnchorPath(string root) { return Path.Combine(root,"anchor.json"); }
    static void Save(string root, RecoveryMethodCheckpoint anchor)
    {
        string temp=AnchorPath(root)+"."+Guid.NewGuid().ToString("N")+".partial";
        try {
            using (var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) {
                byte[] bytes=Encoding.UTF8.GetBytes(Json.Serialize(anchor));file.Write(bytes,0,bytes.Length);file.Flush(true);
            }
            if (File.Exists(AnchorPath(root))) File.Replace(temp,AnchorPath(root),null);else File.Move(temp,AnchorPath(root));
        } finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    static string Folder()
    { string root=Path.Combine(work,Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);return root; }
    static object Plan(string root, string name, string expected, bool content)
    {
        var plan=New("RecoveryMappedFilePlan");Set(plan,"ArchiveRoot",root);Set(plan,"OutputRoot",Path.Combine(root,"payloads"));
        Set(plan,"RelativeOutput",name);Set(plan,"Provenance","owned-content-test");Set(plan,"Length",(long)(2*MiB+73));
        Set(plan,"ExpectedSha256",expected);Set(plan,"ContentAddressed",content);
        var ranges=(IList)plan.GetType().GetField("Ranges").GetValue(plan);var range=New("RecoveryMappedRange");
        Set(range,"ImageOffset",0L);Set(range,"LogicalOffset",0L);Set(range,"Length",(long)(2*MiB+73));ranges.Add(range);return plan;
    }
    static string Run(string root, string name="candidate-{sha256}.bin", string expected=null, bool content=true,
        Action<string> progress=null, CancellationToken cancel=default(CancellationToken))
    {
        var context=New("RecoveryCheckpointContext");Set(context,"Directory",root);Set(context,"Method","fragmented-media");
        Set(context,"SourceSha256",sourceHash);Set(context,"Settings","mapped-content-test-v1");
        if (File.Exists(AnchorPath(root))) Set(context,"Resume",Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(AnchorPath(root))));
        Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a=>Save(root,a)));
        using (var input=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            object publisher=null;
            try {
                publisher=Activator.CreateInstance(App.GetType("UsbRecovery.RecoveryMappedFilePublisher",true),
                    new object[]{input,Plan(root,name,expected,content),context,cancel,null,progress,null});
                return (string)publisher.GetType().GetMethod("Run").Invoke(publisher,null);
            } catch (TargetInvocationException error) { throw error.InnerException; }
            finally { if (publisher!=null) ((IDisposable)publisher).Dispose(); }
        }
    }
    static void ResumeAt(string phase)
    {
        string root=Folder();bool stopped=false;
        using (var cancel=new CancellationTokenSource()) {
            try { Run(root,expected:payloadHash,cancel:cancel.Token,progress:m=>{if(m.Contains(phase))cancel.Cancel();}); }
            catch (OperationCanceledException) { stopped=true; }
        }
        Check(stopped&&File.Exists(AnchorPath(root)),"hash-named copy anchors cancellation at "+phase);
        Check(Run(root,expected:payloadHash)==payloadHash,"hash-named copy resumes at "+phase);
        string result=Path.Combine(root,"payloads","candidate-"+payloadHash+".bin");
        Check(Hash(result)==payloadHash,"published bytes match the expected digest at "+phase);
        Check(Run(root,expected:payloadHash,progress:m=>{throw new Exception("completed publisher repeated a phase");})==payloadHash,"completed publisher verifies without recopy");
    }
    static void Reject(string name, string expected)
    {
        string root=Folder();bool failed=false;
        try { Run(root,name,expected); } catch (IOException) { failed=true; }
        Check(failed,"rejects malformed or mismatching hash plan: "+name);
        Check(!Directory.Exists(Path.Combine(root,"payloads"))||!Directory.GetFiles(Path.Combine(root,"payloads"),"*",SearchOption.AllDirectories).Any(),"failed digest never publishes a payload");
    }
    static void Existing()
    {
        string root=Folder(),output=Path.Combine(root,"payloads","candidate-"+payloadHash+".bin");Directory.CreateDirectory(Path.GetDirectoryName(output));
        File.Copy(image,output);DateTime timestamp=File.GetLastWriteTimeUtc(output);
        Check(Run(root,expected:payloadHash)==payloadHash&&Hash(output)==payloadHash&&File.GetLastWriteTimeUtc(output)==timestamp,"identical preexisting hash-named payload is verified and preserved");
        File.AppendAllText(output,"foreign");string foreign=Hash(output);bool failed=false;
        try { Run(root,expected:payloadHash); } catch (IOException) { failed=true; }
        Check(failed&&Hash(output)==foreign,"changed hash-named payload is neither overwritten nor accepted");
    }
    static void LegacyIdentity()
    {
        string root=Folder();Check(Run(root,"fixed.bin",content:false)==payloadHash,"default fixed-name plan retains the original path behavior");
        var anchor=Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(AnchorPath(root)));
        var envelope=Json.Deserialize<System.Collections.Generic.Dictionary<string,object>>(File.ReadAllText(anchor.Path));
        // Independently reconstruct the pre-extension identity byte layout.
        string identity;
        using (var stream=new MemoryStream()) using (var writer=new BinaryWriter(stream,new UTF8Encoding(false,true))) {
            writer.Write("");writer.Write("payloads/");writer.Write("fixed.bin");writer.Write("owned-content-test");
            writer.Write((long)(2*MiB+73));writer.Write(false);writer.Write(1);writer.Write(0L);writer.Write(0L);writer.Write((long)(2*MiB+73));
            writer.Flush();identity=Hex(stream.ToArray());
        }
        var payload=(System.Collections.Generic.Dictionary<string,object>)envelope["Payload"];
        Check((string)payload["Identity"]==identity,"default plans preserve the exact pre-extension checkpoint identity");
    }
    public static int Main(string[] args)
    {
        try {
            work=Path.Combine(Path.GetFullPath(args[0]),".build","mapped-content-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            image=Path.Combine(work,"owned.dd");byte[] bytes=new byte[2*MiB+73];new Random(7351).NextBytes(bytes);File.WriteAllBytes(image,bytes);sourceHash=payloadHash=Hash(image);
            foreach(string phase in new[]{"mapped bytes 0","mapped bytes 1048576","(ready)","(published)"})ResumeAt(phase);
            Reject("candidate.bin",payloadHash);Reject("{sha256}-{sha256}.bin",payloadHash);Reject("../{sha256}.bin",payloadHash);
            Reject("candidate-{sha256}.bin","invalid");Reject("candidate-{sha256}.bin",new string('0',64));Existing();LegacyIdentity();
            Check(Hash(image)==sourceHash,"all shared-publisher tests preserve their source");
            Console.WriteLine("PASS MappedContentCheckpoint: "+checks+" checks; hash naming, expected digest, cancellation, duplicate preservation and default checkpoint compatibility");return 0;
        } catch (Exception error) { Console.Error.WriteLine(error);return 1; }
    }
}
