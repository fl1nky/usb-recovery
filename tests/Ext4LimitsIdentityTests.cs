using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using UsbRecovery;

public static class Ext4LimitsIdentityTests
{
    static int checks;
    static void Check(bool value,string label) { checks++;if(!value)throw new Exception(label); }
    static void Set(object value,string name,object data) { value.GetType().GetField(name).SetValue(value,data); }
    static string Identity(Ext4Recovery.Limits limits)
    { return (string)typeof(Ext4Recovery).GetMethod("Ext4LimitsIdentity",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[]{limits}); }
    static void Validate(object scope)
    {
        try{scope.GetType().GetMethod("ValidateLimits").Invoke(scope,null);}
        catch(TargetInvocationException error){throw error.InnerException;}
    }
    public static int Main(string[] args)
    {
        var culture=Thread.CurrentThread.CurrentCulture;
        try {
            string root=Path.Combine(Path.GetFullPath(args[0]),".build","ext4-limit-identity-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
            string image=Path.Combine(root,"owned.dd");File.WriteAllText(image,"owned read-only limits scope proof");
            string hash=RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{});
            var limits=new Ext4Recovery.Limits();
            var fields=typeof(Ext4Recovery.Limits).GetFields(BindingFlags.Public|BindingFlags.Instance).OrderBy(x=>x.Name,StringComparer.Ordinal).ToArray();
            // Prime a different member cache order before taking the identity.
            foreach(var field in fields.Reverse())field.GetValue(limits);
            string before=Identity(limits);Check(before.Length==64,"limits have a bounded stable digest");
            using(var input=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                object c=Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
                Set(c,"Input",input);Set(c,"Limits",limits);Set(c,"Cancel",CancellationToken.None);
                object context=Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
                Set(context,"Directory",root);Set(context,"Method","ext4");Set(context,"SourceSha256",hash);
                var type=typeof(Ext4Recovery).GetNestedType("MetadataSourceScope",BindingFlags.NonPublic);
                using(var scope=(IDisposable)Activator.CreateInstance(type,BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance,null,new[]{c,context},CultureInfo.InvariantCulture)) {
                    foreach(var field in fields) {
                        object original=field.GetValue(limits);
                        if(field.FieldType==typeof(int))field.SetValue(limits,(int)original+1);else field.SetValue(limits,(long)original+1);
                        bool refused=false;try{Validate(scope);}catch(IOException){refused=true;}
                        Check(Identity(limits)!=before&&refused,"each scalar limit remains bound: "+field.Name);
                        field.SetValue(limits,original);Validate(scope);Check(Identity(limits)==before,"restoring "+field.Name+" restores the same binding");
                    }
                    foreach(string name in new[]{"en-US","fr-FR","ar-SA"}) {
                        Thread.CurrentThread.CurrentCulture=CultureInfo.GetCultureInfo(name);
                        foreach(var field in fields.Reverse())field.GetValue(limits);
                        Validate(scope);Check(Identity(limits)==before,"field-cache order and culture cannot change equivalent limits");
                    }
                    using(var nested=(IDisposable)Activator.CreateInstance(type,BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance,null,new[]{c,context},CultureInfo.InvariantCulture))
                    {Validate(nested);Check(Identity(limits)==before,"nested source lease retains the same complete limit binding");}
                    Validate(scope);
                }
            }
            Check(RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{})==hash,"scope and limit checks leave source bytes unchanged");
            Console.WriteLine("PASS Ext4LimitsIdentity: "+checks+" checks; every current limit, culture, field order and nested scope; no devices");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
        finally{Thread.CurrentThread.CurrentCulture=culture;}
    }
}
