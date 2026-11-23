// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UsbRecovery;

public static class RecoveryNativeProtocolTests
{
    static int checks;
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static byte[] Wire(byte kind,ulong sequence,byte[] payload=null,uint? advertised=null)
    {
        payload=payload??new byte[0];
        using(var bytes=new MemoryStream()) using(var writer=new BinaryWriter(bytes,Encoding.UTF8)) {
            writer.Write(Encoding.ASCII.GetBytes("URC1"));writer.Write((byte)1);writer.Write(kind);writer.Write((ushort)0);
            writer.Write(sequence);writer.Write(advertised??(uint)payload.Length);writer.Write(0u);writer.Write(payload);
            writer.Flush();return bytes.ToArray();
        }
    }
    static void Reject(byte[] wire,string code)
    {
        using(var input=new MemoryStream(wire,false)) using(var output=new MemoryStream()) {
            var channel=new RecoveryNativeProtocol(input,output,CancellationToken.None);bool failed=false;
            try { channel.Read(); } catch(IOException error) { failed=error.Message==code; }
            Check(failed,"managed native reader rejects "+code);
            failed=false;try { channel.Read(); } catch(IOException error) { failed=error.Message=="NATIVE_PROTOCOL_ALREADY_FAILED"; }
            Check(failed&&output.Length==0,"failed protocol cannot acknowledge or restart after "+code);
        }
    }
    sealed class OneByte:MemoryStream
    { internal OneByte(byte[] bytes):base(bytes,false){} public override int Read(byte[] b,int at,int count){return base.Read(b,at,Math.Min(1,count));} }
    static void MemoryCases()
    {
        var header=Wire(2,1,new byte[]{0,13,10,255});
        using(var input=new OneByte(header)) using(var output=new MemoryStream()) {
            var channel=new RecoveryNativeProtocol(input,output,CancellationToken.None);var message=channel.Read();
            Check(message.Kind==RecoveryNativeKind.Read&&message.Sequence==1&&message.Payload.Length==4&&message.Payload[3]==255,"one-byte physical reads preserve a binary frame");
            channel.Reply(message,RecoveryNativeKind.Bytes,new byte[]{0,13,10,255});
            Check(Convert.ToBase64String(output.ToArray())==Convert.ToBase64String(Wire(3,1,new byte[]{0,13,10,255})),"managed reply is byte-for-byte compatible with native schema");
        }
        byte[] bad=Wire(2,1);bad[0]=0;Reject(bad,"NATIVE_PROTOCOL_HEADER_INVALID");
        bad=Wire(2,1);bad[4]=2;Reject(bad,"NATIVE_PROTOCOL_HEADER_INVALID");
        bad=Wire(2,1);bad[6]=1;Reject(bad,"NATIVE_PROTOCOL_HEADER_INVALID");
        bad=Wire(2,1);bad[20]=1;Reject(bad,"NATIVE_PROTOCOL_HEADER_INVALID");
        foreach(byte kind in new byte[]{0,3,7,10,13,255})Reject(Wire(kind,1),"NATIVE_PROTOCOL_HEADER_INVALID");
        Reject(Wire(2,0),"NATIVE_PROTOCOL_SEQUENCE_INVALID");Reject(Wire(2,2),"NATIVE_PROTOCOL_SEQUENCE_INVALID");
        Reject(Wire(2,1,advertised:UInt32.MaxValue),"NATIVE_PROTOCOL_PAYLOAD_LIMIT");
        Reject(Wire(2,1,advertised:1048577),"NATIVE_PROTOCOL_PAYLOAD_LIMIT");
        Reject(new byte[]{85,82,67,49},"NATIVE_PROTOCOL_EOF");Reject(Wire(2,1,new byte[]{1},4),"NATIVE_PROTOCOL_EOF");
        using(var input=new MemoryStream(Wire(4,1),false)) using(var output=new MemoryStream()) {
            var channel=new RecoveryNativeProtocol(input,output,CancellationToken.None);channel.Read();bool denied=false;
            try { channel.Read(); } catch(IOException e) { denied=e.Message=="NATIVE_PROTOCOL_ACK_REQUIRED"; }
            Check(denied&&output.Length==0,"an unacknowledged request cannot be skipped");
        }
        using(var input=new MemoryStream(Wire(4,1),false)) using(var output=new MemoryStream()) {
            var channel=new RecoveryNativeProtocol(input,output,CancellationToken.None);var message=channel.Read();bool denied=false;
            try { channel.Reply(new RecoveryNativeMessage(message.Kind,message.Sequence,message.Payload),RecoveryNativeKind.Ack,null); }
            catch(IOException e) { denied=e.Message=="NATIVE_PROTOCOL_REPLY_UNPLANNED"; }
            Check(denied&&output.Length==0,"matching integers do not make a fabricated frame the pending request");
        }
        using(var input=new MemoryStream(Wire(4,1),false)) using(var output=new MemoryStream()) {
            var channel=new RecoveryNativeProtocol(input,output,CancellationToken.None);var message=channel.Read();bool denied=false;
            try { channel.Reply(message,RecoveryNativeKind.Bytes,new byte[0]); }catch(IOException e){denied=e.Message=="NATIVE_PROTOCOL_REPLY_KIND_INVALID";}
            Check(denied&&output.Length==0,"a metadata checkpoint cannot be acknowledged as source bytes");
        }
        using(var input=new MemoryStream(Wire(2,1),false)) using(var output=new MemoryStream())using(var cancel=new CancellationTokenSource()) {
            var channel=new RecoveryNativeProtocol(input,output,cancel.Token);var message=channel.Read();cancel.Cancel();bool stopped=false;
            try{channel.Reply(message,RecoveryNativeKind.Bytes,new byte[]{1});}catch(OperationCanceledException){stopped=true;}
            Check(stopped&&output.Length==0,"cancellation before acknowledgement sends no success bytes");
        }
        using(var input=new MemoryStream(Wire(4,1),false)) using(var output=new MemoryStream()) {
            var channel=new RecoveryNativeProtocol(input,output,CancellationToken.None);var message=channel.Read();channel.Reply(message,RecoveryNativeKind.Cancel,null);
            Check(Convert.ToBase64String(output.ToArray())==Convert.ToBase64String(Wire(10,1)),"explicit cancellation uses the pending sequence");
            bool denied=false;try{channel.Read();}catch(IOException e){denied=e.Message=="NATIVE_PROTOCOL_ALREADY_FAILED";}
            Check(denied,"a cancelled connection cannot continue as a new transaction");
        }
    }
    static void ActualNative(string executable)
    {
        Type jobType=typeof(RecoverySession).Assembly.GetType("UsbRecovery.ProcessJob",true);
        using(var process=new Process()) using(var job=(IDisposable)Activator.CreateInstance(jobType,new object[]{128L*1024*1024})) {
            process.StartInfo=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Path.GetDirectoryName(executable)};
            process.Start();jobType.GetMethod("Attach").Invoke(job,new object[]{process});
            var diagnostic=new MemoryStream();
            var errors=Task.Run(()=>{byte[] bytes=new byte[4096];int count;while((count=process.StandardError.BaseStream.Read(bytes,0,bytes.Length))>0){if(diagnostic.Length<4096)diagnostic.Write(bytes,0,(int)Math.Min(count,4096-diagnostic.Length));}});
            var exchange=Task.Run(()=>{
                var channel=new RecoveryNativeProtocol(process.StandardOutput.BaseStream,process.StandardInput.BaseStream,CancellationToken.None);
                var read=channel.Read();Check(read.Kind==RecoveryNativeKind.Read&&read.Payload.Length==12&&BitConverter.ToUInt64(read.Payload,0)==512&&BitConverter.ToUInt32(read.Payload,8)==4,"actual compiled C source request decoded by product protocol");
                channel.Reply(read,RecoveryNativeKind.Bytes,new byte[]{0,13,10,255});
                var snapshot=channel.Read();Check(snapshot.Kind==RecoveryNativeKind.Snapshot&&Convert.ToBase64String(snapshot.Payload)=="AA0K/w==","actual C echo confirms binary reply without text translation");
                channel.Reply(snapshot,RecoveryNativeKind.Ack,null);
                var done=channel.Read();Check(done.Kind==RecoveryNativeKind.Done&&done.Payload.Length==0,"actual C completion follows parent snapshot acknowledgement");
                channel.Reply(done,RecoveryNativeKind.Ack,null);
            });
            try {
                Check(exchange.Wait(10000),"managed/native exchange completes within its owned timeout");
                Check(process.WaitForExit(10000)&&process.ExitCode==0&&errors.Wait(10000),"contained native worker terminates successfully with all pipes drained");
            } finally {
                jobType.GetMethod("Stop").Invoke(job,null); try{Task.WaitAll(new[]{exchange,errors},1000);}catch{}
                if(!exchange.IsCompleted||exchange.IsFaulted)Console.Error.WriteLine("Owned native diagnostic: exit="+(process.HasExited?process.ExitCode.ToString():"running")+" "+Encoding.UTF8.GetString(diagnostic.ToArray()));
                diagnostic.Dispose();
            }
        }
    }
    public static int Main(string[] args)
    {
        try { MemoryCases();ActualNative(Path.GetFullPath(args[0]));Console.WriteLine("PASS RecoveryNativeProtocol: "+checks+" checks; actual managed/native pipes and contained worker; no filesystem recovery or durable checkpoint claim");return 0; }
        catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
