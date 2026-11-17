// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class NativeNtfsCheckpointTests
{
    static int checks;
    static string evidence;
    static void Check(bool condition, string label)
    { if (!condition) throw new Exception(label); checks++; }
    static void Invalid(Action action, string label)
    {
        try { action(); } catch (IOException) { checks++; return; }
        throw new Exception("Expected rejection: " + label);
    }
    static void ErrorCode(Action action, string code, string label)
    {
        try { action(); } catch (IOException error) { Check(error.Message==code,label);return; }
        throw new Exception("Expected error code: " + label);
    }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (n,total) => { }); }
    static byte[] Body(Action<BinaryWriter> write)
    { using (var stream = new MemoryStream()) { using (var writer = new BinaryWriter(stream, Encoding.UTF8, true)) write(writer); return stream.ToArray(); } }
    static void Text(BinaryWriter writer, string value)
    { byte[] bytes = Encoding.UTF8.GetBytes(value); writer.Write((uint)bytes.Length); writer.Write(bytes); }
    static RecoveryNativeMessage Message(RecoveryNativeKind kind, byte[] body)
    { return new RecoveryNativeMessage(kind, 1, body); }
    static byte[] Hello(long start)
    { return Body(w => { w.Write(1048576L); w.Write(0L); w.Write(1048576L); w.Write(start); w.Write(512U); w.Write(1U); }); }
    static byte[] Layout(long records)
    { return Body(w => { w.Write(records); w.Write(4096U); w.Write(1024U); w.Write(512U); w.Write(1U); }); }
    static byte[] Record(uint streams)
    { return Body(w => { w.Write(1U); w.Write(0L); w.Write(3U); w.Write(0U); w.Write(100U); w.Write(streams); Text(w,"фото.jpg"); Text(w,"../metadata only"); }); }
    static byte[] Resident(uint index, uint flags, byte[] bytes)
    {
        return Body(w => { w.Write(0L); w.Write(index); w.Write(flags); w.Write((long)bytes.Length); w.Write((long)bytes.Length);
            w.Write(0L); w.Write(100U); Text(w,""); w.Write((uint)bytes.Length); w.Write(bytes); });
    }
    static RecoveryNativeNtfsPlans Ready()
    {
        var decoder = new RecoveryNativeNtfsPlans(1048576,0,1048576,0,512);
        decoder.Accept(Message(RecoveryNativeKind.Hello,Hello(0)));
        decoder.Accept(Message(RecoveryNativeKind.Snapshot,Layout(1))); return decoder;
    }
    static void DecoderCases()
    {
        var decoder = Ready();
        var record = (RecoveryNativeNtfsRecord)decoder.Accept(Message(RecoveryNativeKind.Record,Record(1)));
        Check(record.Name == "фото.jpg" && record.Parent == "../metadata only", "Unicode and source names retained as metadata");
        var stream = (RecoveryNativeNtfsStream)decoder.Accept(Message(RecoveryNativeKind.Stream,Resident(0,1,new byte[]{1,2,3})));
        Check(stream.Resident.SequenceEqual(new byte[]{1,2,3}) && stream.Length == 3, "resident body decoded exactly");
        decoder.Accept(Message(RecoveryNativeKind.EndRecord,Body(w => { w.Write(1L); w.Write(2U); })));
        Check(decoder.NextOrdinal == 1, "exact record cursor accepted");
        decoder.Accept(Message(RecoveryNativeKind.Done,new byte[0]));
        Invalid(() => decoder.Accept(Message(RecoveryNativeKind.Done,new byte[0])), "repeated completion");
        Invalid(() => Ready().Accept(Message(RecoveryNativeKind.Done,new byte[0])), "premature success");
        Invalid(() => Ready().Accept(Message(RecoveryNativeKind.Snapshot,Layout(1))), "repeated geometry");
        Invalid(() => Ready().Accept(Message(RecoveryNativeKind.Record,Record(4097))), "stream count cap");
        Invalid(() => Ready().Accept(Message(RecoveryNativeKind.Stream,Resident(0,1,new byte[0]))), "unplanned stream");
        Invalid(() => Ready().Accept(Message(RecoveryNativeKind.Read,Body(w => { w.Write(1048575L); w.Write(2U); }))), "source read bounds");
        for (int size = 0; size < 40; size++) {
            int n = size; Invalid(() => new RecoveryNativeNtfsPlans(1048576,0,1048576,0,512)
                .Accept(Message(RecoveryNativeKind.Hello,Hello(0).Take(n).ToArray())), "truncated hello");
        }
        foreach (Action<byte[]> change in new Action<byte[]>[] {
            b => b[0] = 2, b => b[4] = 1, b => b[16] = 1, b => b[20] = 101, b => b[25] = 0x20, b => b[32] = 0xff }) {
            byte[] bytes = Record(1); change(bytes);
            Invalid(() => Ready().Accept(Message(RecoveryNativeKind.Record,bytes)), "record schema/ordinal/flags/percent/text bounds");
        }
        var badText = Record(1); badText[32] = 0xff;
        Invalid(() => Ready().Accept(Message(RecoveryNativeKind.Record,badText)), "invalid UTF8");
        var unfinished = Ready(); unfinished.Accept(Message(RecoveryNativeKind.Record,Record(1)));
        Invalid(() => unfinished.Accept(Message(RecoveryNativeKind.EndRecord,Body(w => {w.Write(1L);w.Write(2U);}))), "missing stream");
        Invalid(() => unfinished.Accept(Message(RecoveryNativeKind.Read,Body(w => {w.Write(0L);w.Write(1U);}))), "sticky typed failure");
        var trailing = Ready();
        Invalid(() => trailing.Accept(Message(RecoveryNativeKind.Record,Record(0).Concat(new byte[]{0}).ToArray())), "trailing record bytes");
        var badFlags = Ready(); badFlags.Accept(Message(RecoveryNativeKind.Record,Record(1)));
        Invalid(() => badFlags.Accept(Message(RecoveryNativeKind.Stream,Resident(0,9,new byte[0]))), "unknown stream flags");
        var badIndex = Ready(); badIndex.Accept(Message(RecoveryNativeKind.Record,Record(1)));
        Invalid(() => badIndex.Accept(Message(RecoveryNativeKind.Stream,Resident(1,1,new byte[0]))), "stream index gap");
        var nonresident = Ready(); nonresident.Accept(Message(RecoveryNativeKind.Record,Record(1)));
        byte[] run = Body(w => {w.Write(0L);w.Write(0U);w.Write(0U);w.Write(4096L);w.Write(4096L);w.Write(4096L);w.Write(100U);Text(w,"");w.Write(1U);w.Write(0L);w.Write(-1L);w.Write(1L);});
        var sparse = (RecoveryNativeNtfsStream)nonresident.Accept(Message(RecoveryNativeKind.Stream,run));
        Check(sparse.Runs.Count == 1 && sparse.Runs[0].Lcn == -1, "sparse run remains explicit");
        for (int at = 48; at < run.Length; at++) {
            int stop = at; var target = Ready(); target.Accept(Message(RecoveryNativeKind.Record,Record(1)));
            Invalid(() => target.Accept(Message(RecoveryNativeKind.Stream,run.Take(stop).ToArray())), "truncated run");
        }
        foreach(Action<byte[]> change in new Action<byte[]>[] {
            b=>b[52]=1, b=>Buffer.BlockCopy(BitConverter.GetBytes(-3L),0,b,60,8),
            b=>Buffer.BlockCopy(BitConverter.GetBytes(256L),0,b,60,8),
            b=>Buffer.BlockCopy(BitConverter.GetBytes(Int64.MaxValue),0,b,68,8),
            b=>Buffer.BlockCopy(BitConverter.GetBytes(32769U),0,b,48,4) }) {
            byte[] damaged=(byte[])run.Clone(); change(damaged);
            var target=Ready();target.Accept(Message(RecoveryNativeKind.Record,Record(1)));
            Invalid(()=>target.Accept(Message(RecoveryNativeKind.Stream,damaged)),"run continuity/location/overflow/count");
        }
        foreach(uint cluster in new uint[]{0,256,513,3072,4194304}) {
            var target=new RecoveryNativeNtfsPlans(1048576,0,1048576,0,512);target.Accept(Message(RecoveryNativeKind.Hello,Hello(0)));
            byte[] geometry=Layout(1);Buffer.BlockCopy(BitConverter.GetBytes(cluster),0,geometry,8,4);
            Invalid(()=>target.Accept(Message(RecoveryNativeKind.Snapshot,geometry)),"invalid cluster geometry");
        }
    }
    sealed class FailedRead : FileStream
    {
        readonly bool shortRead;
        int calls;
        internal FailedRead(string path,bool shortResult) : base(path,FileMode.Open,FileAccess.Read,FileShare.Read)
        { shortRead=shortResult; }
        public override int Read(byte[] bytes,int at,int count)
        {
            if(!shortRead)throw new IOException("injected source read failure");
            if(calls++!=0)return 0;
            return base.Read(bytes,at,Math.Min(count,127));
        }
    }
    static RecoveryCheckpointContext Context(string root, string sourceHash, RecoveryMethodCheckpoint resume,
        Action<RecoveryMethodCheckpoint> save)
    { return new RecoveryCheckpointContext { Directory = root, Method = "ntfs", SourceSha256 = sourceHash, Settings = "native-cache-test-v1", Resume = resume, Commit = save }; }
    static void CacheCases()
    {
        string image = Path.Combine(evidence,"cache-source.dd"), output = Path.Combine(evidence,"cache");
        byte[] bytes = Enumerable.Range(0,RecoveryNativeReadCache.PageBytes*3+123).Select(n => (byte)(n*37)).ToArray(); File.WriteAllBytes(image,bytes);
        string hash = Hash(image); RecoveryMethodCheckpoint anchor = null;
        using (var input = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))
        using (var verified = new RecoveryVerifiedImage(input,hash,CancellationToken.None)) {
            var cache = new RecoveryNativeReadCache(input,verified,Context(output,hash,null,a => anchor=a),0,bytes.Length,1024*1024,CancellationToken.None);
            Check(cache.Read(65530,30).SequenceEqual(bytes.Skip(65530).Take(30)), "read spans offset-keyed pages");
            Check(cache.PhysicalReadBytes == 131072 && anchor != null, "two pages committed before delivery");
            var resumed = new RecoveryNativeReadCache(input,verified,Context(output,hash,anchor,a=>anchor=a),0,bytes.Length,1024*1024,CancellationToken.None);
            Check(resumed.Read(65536,15).SequenceEqual(bytes.Skip(65536).Take(15)) && resumed.Read(0,7).SequenceEqual(bytes.Take(7)), "resume tolerates changed native request order");
            Check(resumed.PhysicalReadBytes == 0, "acknowledged pages avoid physical reread");
            Check(resumed.Read(bytes.Length-10,10).SequenceEqual(bytes.Skip(bytes.Length-10)), "bounded short final page");
            Invalid(() => resumed.Read(-1,1), "negative read"); Invalid(() => resumed.Read(bytes.Length,1), "past source");
            Invalid(() => resumed.Read(0,0), "empty read"); Invalid(() => resumed.Read(0,1048577), "oversized read");
            Invalid(() => new RecoveryNativeReadCache(input,verified,Context(output,hash,anchor,a=>{}),0,bytes.Length,2*1024*1024,CancellationToken.None), "cache limit binding");
            string blob = Directory.GetFiles(Path.Combine(output,"ntfs.state","read-cache"),"0000000000000000-*.bin").Single();
            byte[] damaged = File.ReadAllBytes(blob); damaged[0] ^= 1; File.WriteAllBytes(blob,damaged);
            Invalid(() => resumed.Read(0,1), "same-length cache corruption");
            File.WriteAllBytes(blob,bytes.Take(65536).ToArray());
            File.Move(blob,blob+".saved"); Invalid(() => resumed.Read(0,1), "missing acknowledged page"); File.Move(blob+".saved",blob);
            var mutable = Context(Path.Combine(evidence,"mutated-cache"),hash,null,a=>{});
            var bound = new RecoveryNativeReadCache(input,verified,mutable,0,bytes.Length,1024*1024,CancellationToken.None);
            mutable.Settings += "changed"; Invalid(() => bound.Read(0,1), "mutated context");
            string failedRoot = Path.Combine(evidence,"failed-parent");
            var failed = new RecoveryNativeReadCache(input,verified,Context(failedRoot,hash,null,a=>{throw new IOException("injected parent failure");}),0,bytes.Length,1024*1024,CancellationToken.None);
            Invalid(() => failed.Read(0,4), "parent failure prevents byte acknowledgement");
            var orphan = new RecoveryNativeReadCache(input,verified,Context(failedRoot,hash,null,a=>{}),0,bytes.Length,1024*1024,CancellationToken.None);
            Check(orphan.Read(0,4).SequenceEqual(bytes.Take(4)) && orphan.PhysicalReadBytes == 65536, "orphan reread and verified before adoption");
            var limited = new RecoveryNativeReadCache(input,verified,Context(Path.Combine(evidence,"limited"),hash,null,a=>{}),0,bytes.Length,65536,CancellationToken.None);
            limited.Read(0,1); Invalid(() => limited.Read(65536,1), "cache limit fails explicitly");
            using (var stop = new CancellationTokenSource()) {
                var cancelled = new RecoveryNativeReadCache(input,verified,Context(Path.Combine(evidence,"cancelled"),hash,null,a=>{}),0,bytes.Length,65536,stop.Token);
                stop.Cancel(); try { cancelled.Read(0,1); throw new Exception("cancellation ignored"); } catch (OperationCanceledException) { checks++; }
            }
        }
        Check(Hash(image)==hash,"cache leaves source unchanged");
        foreach(bool shortRead in new[]{false,true}) {
            RecoveryMethodCheckpoint saved=null;
            using(var failedSource=new FailedRead(image,shortRead))
            using(var verified=new RecoveryVerifiedImage(failedSource,hash,CancellationToken.None)) {
                string failureRoot=Path.Combine(evidence,shortRead?"short-source":"failed-source");
                var cache=new RecoveryNativeReadCache(failedSource,verified,Context(failureRoot,hash,null,a=>saved=a),0,bytes.Length,65536,CancellationToken.None);
                Invalid(()=>cache.Read(0,4),"real source exception/short read propagates");
                Check(saved==null && cache.CachedBytes==0 && !Directory.Exists(failureRoot),"failed source page creates no acknowledged cache or false success");
            }
        }
    }
    sealed class ScanState { public long Cursor; public RecoveryMethodCheckpoint Cache; }
    static void FileCases()
    {
        string image=Path.Combine(evidence,"copy-source.dd"), root=Path.Combine(evidence,"copy"), output=Path.Combine(root,"ntfs");
        byte[] bytes=Enumerable.Range(0,4*1024*1024).Select(n=>(byte)(n*19+n/4096)).ToArray();File.WriteAllBytes(image,bytes);string hash=Hash(image);
        var record=new RecoveryNativeNtfsRecord {Ordinal=77,Sequence=5,Streams=1,Name="../../photo.JPG"};
        var stream=new RecoveryNativeNtfsStream {Ordinal=77,Index=0,Length=2*1024*1024+123,Initialized=2*1024*1024+123,Percent=100};
        stream.Runs.Add(new RecoveryNativeNtfsRun {Vcn=0,Lcn=0,Clusters=256});
        stream.Runs.Add(new RecoveryNativeNtfsRun {Vcn=256,Lcn=-1,Clusters=1});
        stream.Runs.Add(new RecoveryNativeNtfsRun {Vcn=257,Lcn=512,Clusters=256});
        var file=RecoveryNativeNtfsFiles.Build(record,stream,0,bytes.Length,4096,root,output,8*1024*1024);
        Check(file.Status=="candidate" && file.Parts.Count==1 && file.MissingBytes==0 && file.MappedBytes==stream.Length,"fragmented/sparse stream maps exact logical size");
        Check(file.Parts[0].Plan.RelativeOutput=="record-77-5-stream-0.jpg","untrusted names cannot become output paths");
        byte[] expected=bytes.Take(1024*1024).Concat(new byte[4096]).Concat(bytes.Skip(2*1024*1024).Take(1024*1024+123-4096)).ToArray();
        RecoveryMethodCheckpoint anchor=null;
        using(var input=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))
        using(var verified=new RecoveryVerifiedImage(input,hash,CancellationToken.None)) {
            using(var stop=new CancellationTokenSource()) {
                var checkpoint=Context(root,hash,null,a=>anchor=a);
                try {
                    using(var publisher=new RecoveryMappedFilePublisher(input,file.Parts[0].Plan,checkpoint,stop.Token,()=>{},text=>{
                        if(text.Contains("mapped bytes 1048576 (copy"))stop.Cancel();
                    },verified))publisher.Run();
                    throw new Exception("copy did not cancel");
                }catch(OperationCanceledException){Check(anchor!=null,"file copy commits first MiB before cancellation");}
                Check(!File.Exists(Path.Combine(output,file.Parts[0].Plan.RelativeOutput)),"cancelled copy is not published as complete");
            }
            string digest;
            using(var publisher=new RecoveryMappedFilePublisher(input,file.Parts[0].Plan,Context(root,hash,anchor,a=>anchor=a),CancellationToken.None,()=>{},null,verified))digest=publisher.Run();
            string destination=Path.Combine(output,file.Parts[0].Plan.RelativeOutput);
            Check(File.ReadAllBytes(destination).SequenceEqual(expected) && Hash(destination)==digest,"resumed fragmented copy publishes exact expected bytes");
            File.Delete(destination);
            using(var repair=new RecoveryMappedFilePublisher(input,file.Parts[0].Plan,Context(root,hash,anchor,a=>anchor=a),CancellationToken.None,()=>{},null,verified))
                Check(repair.Run()==digest && File.ReadAllBytes(destination).SequenceEqual(expected),"missing published file repaired from anchored plan");
            byte[] changed=File.ReadAllBytes(destination);changed[0]^=1;File.WriteAllBytes(destination,changed);
            Invalid(()=>{using(var publisher=new RecoveryMappedFilePublisher(input,file.Parts[0].Plan,Context(root,hash,anchor,a=>anchor=a),CancellationToken.None,()=>{},null,verified))publisher.Run();},"modified output never overwritten as successful resume");
        }
        Check(Hash(image)==hash,"cancel/resume/repair preserves physical source bytes");
        stream.Runs[1].Lcn=-2;
        var partial=RecoveryNativeNtfsFiles.Build(record,stream,0,bytes.Length,4096,root,output,8*1024*1024);
        Check(partial.Status=="missing-segments" && partial.Parts.Count==2 && partial.MissingBytes==4096,"unknown segment produces two explicit partial files instead of fabricated zeroes");
        Check(partial.Parts[1].LogicalOffset==257*4096 && partial.Parts[1].Plan.Ranges[0].LogicalOffset==0,"partial file map retains original logical offset");
        stream.Initialized=1024*1024;
        var uninitialized=RecoveryNativeNtfsFiles.Build(record,stream,0,bytes.Length,4096,root,output,8*1024*1024);
        Check(uninitialized.Parts.Count==1 && uninitialized.MissingBytes==0 && uninitialized.Parts[0].Plan.Ranges.Skip(1).All(r=>r.ImageOffset==-1),"uninitialized tail is known logical zeroes");
        stream.Flags=4;var encrypted=RecoveryNativeNtfsFiles.Build(record,stream,0,bytes.Length,4096,root,output,8*1024*1024);
        Check(encrypted.Status=="encrypted-unavailable" && encrypted.Parts.Count==0 && encrypted.MissingBytes==stream.Length,"EFS is not presented as recovered plaintext");
        stream.Flags=2;Check(RecoveryNativeNtfsFiles.Build(record,stream,0,bytes.Length,4096,root,output,8*1024*1024).Status=="compressed-unavailable","compression needs a decoder rather than raw concatenation");
        stream.Flags=0;Invalid(()=>RecoveryNativeNtfsFiles.Build(record,stream,0,bytes.Length,4096,root,output,1),"file size limit");
    }
    static void NativeScan(string worker, string image)
    {
        string hash = Hash(image), root = Path.Combine(evidence,"actual-native");
        var tools = new List<RecoveryNativeToolFile>();
        foreach (string path in new[]{worker}.Concat(Directory.GetFiles(Path.GetDirectoryName(worker),"*.dll")))
            tools.Add(new RecoveryNativeToolFile { Path=path, Sha256=Hash(path) });
        long volume; using(var source = File.OpenRead(image)) { byte[] boot = new byte[512]; source.Read(boot,0,512); volume=checked((long)BitConverter.ToUInt64(boot,40)*512); }
        RecoveryMethodCheckpoint parent = null; int seen = 0; long final = 0;
        for (int attempt = 0; attempt < 2; attempt++) {
            using (var input = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))
            using (var verified = new RecoveryVerifiedImage(input,hash,CancellationToken.None))
            using (var stop = new CancellationTokenSource()) {
                var parentContext=Context(root,hash,parent,a=>parent=a);
                var journal=new RecoveryMethodJournal<ScanState>(image,new ScanState(),parentContext,stop.Token);
                ScanState state=journal.Payload; long start=state.Cursor;
                var cacheContext=Context(Path.Combine(root,"ntfs.state","cache"),hash,state.Cache,a=>{
                    var next=new ScanState {Cursor=state.Cursor,Cache=a}; journal.Save(next);state=next;
                });
                var cache=new RecoveryNativeReadCache(input,verified,cacheContext,0,volume,16*1024*1024,stop.Token);
                var decoder=new RecoveryNativeNtfsPlans(input.Length,0,volume,start,512);
                bool finished=false;
                try {
                    RecoveryNativeWorker.Run(tools,new[]{image,"0",RecoveryNativeWorker.Number(volume),RecoveryNativeWorker.Number(start),"512"},TimeSpan.FromSeconds(180),stop.Token,channel=>{
                        while(!finished) {
                            var message=channel.Read(); object value=decoder.Accept(message); byte[] reply=null;
                            if(message.Kind==RecoveryNativeKind.Read) {
                                var read=(RecoveryMappedRange)value;reply=cache.Read(read.ImageOffset,(int)read.Length);
                            } else if(message.Kind==RecoveryNativeKind.Stream) {
                                var stream=(RecoveryNativeNtfsStream)value;
                                Check(stream.Ordinal==41 && stream.Resident!=null && Encoding.ASCII.GetString(stream.Resident)=="Contents here","actual original NTFS reader yields expected resident stream");seen++;
                                var record=new RecoveryNativeNtfsRecord {Ordinal=41,Sequence=1,Streams=1,Name="file.txt"};
                                var file=RecoveryNativeNtfsFiles.Build(record,stream,0,volume,decoder.ClusterBytes,root,Path.Combine(root,"ntfs"),1024*1024);
                                using(var publisher=new RecoveryMappedFilePublisher(input,file.Parts[0].Plan,
                                    Context(Path.Combine(root,"ntfs.state","file-41"),hash,null,a=>{}),stop.Token,()=>{},null,verified))publisher.Run();
                                Check(File.ReadAllText(Path.Combine(root,"ntfs",file.Parts[0].Plan.RelativeOutput))=="Contents here","actual native resident plan publishes exact recovered bytes");
                            } else if(message.Kind==RecoveryNativeKind.EndRecord) {
                                var next=new ScanState {Cursor=decoder.NextOrdinal,Cache=state.Cache};journal.Save(next);state=next;
                                if(attempt==0 && state.Cursor==42)stop.Cancel();
                            } else if(message.Kind==RecoveryNativeKind.Done) {finished=true;final=decoder.NextOrdinal;}
                            channel.Reply(message,message.Kind==RecoveryNativeKind.Read?RecoveryNativeKind.Bytes:RecoveryNativeKind.Ack,reply);
                        }
                    });
                    Check(attempt==1 && finished,"resumed contained worker reaches verified full-table completion");
                } catch(OperationCanceledException) {
                    Check(attempt==0 && state.Cursor==42 && !finished,"cancellation after durable cursor before native acknowledgement");
                }
                if(attempt==1)Check(start==42 && decoder.Records==2304 && final==2304,"native worker starts at saved ordinal and proves complete traversal");
            }
        }
        Check(seen==1,"resume avoids re-emitting completed deleted record");
        Check(Hash(image)==hash,"native cancellation/resume leaves source unchanged");
        var changed = tools.Select(x=>new RecoveryNativeToolFile {Path=x.Path,Sha256=x.Sha256}).ToList(); changed[0].Sha256=new string('0',64);
        Invalid(()=>RecoveryNativeWorker.Run(changed,new string[0],TimeSpan.FromSeconds(1),CancellationToken.None,c=>{}),"worker digest rejected before launch");
        ErrorCode(()=>RecoveryNativeWorker.Run(tools,new[]{image,"0",RecoveryNativeWorker.Number(volume),"0","512"},TimeSpan.FromMilliseconds(150),CancellationToken.None,c=>{var first=c.Read();Thread.Sleep(300);c.Reply(first,RecoveryNativeKind.Ack,null);}),"NATIVE_WORKER_TIMEOUT","deadline terminates owned worker awaiting acknowledgement");
    }
    static int VolumeRun(string root,string image,IList<RecoveryNativeToolFile> tools,long volume,
        RecoveryMethodCheckpoint resume,Action<RecoveryMethodCheckpoint> save,CancellationToken cancel,Action<string> progress)
    {
        string hash=Hash(image);
        using(var source=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))
        using(var verified=new RecoveryVerifiedImage(source,hash,cancel)) {
            var controller=new RecoveryNativeNtfsVolume(source,verified,Context(root,hash,resume,save),tools,0,volume,512,
                root,Path.Combine(root,"ntfs"),8*1024*1024,16*1024*1024,1000,TimeSpan.FromSeconds(180),cancel,progress);
            return controller.Run();
        }
    }
    static void VolumeCases(string worker,string image)
    {
        var tools=new List<RecoveryNativeToolFile>();
        foreach(string path in new[]{worker}.Concat(Directory.GetFiles(Path.GetDirectoryName(worker),"*.dll")))
            tools.Add(new RecoveryNativeToolFile {Path=path,Sha256=Hash(path)});
        long volume;using(var source=File.OpenRead(image)){byte[] boot=new byte[512];source.Read(boot,0,512);volume=checked((long)BitConverter.ToUInt64(boot,40)*512);}
        string root=Path.Combine(evidence,"volume-controller");RecoveryMethodCheckpoint anchor=null;
        using(var stop=new CancellationTokenSource()) {
            try {
                VolumeRun(root,image,tools,volume,null,a=>anchor=a,stop.Token,text=>{if(text=="ntfs: MFT cursor 42")stop.Cancel();});
                throw new Exception("volume did not cancel");
            }catch(OperationCanceledException){Check(anchor!=null,"volume cursor cancellation preserves parent anchor");}
        }
        string data=Directory.GetFiles(Path.Combine(root,"ntfs"),"record-*").Single();
        Check(File.ReadAllText(data)=="Contents here","volume controller publishes native resident candidate before cursor acknowledgement");
        Check(VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null)==1,"volume controller resumes native scan and returns one file");
        string report=Path.Combine(root,"ntfs","ntfs-volume.json"), reportHash=Hash(report);
        File.Delete(data);
        Check(VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null)==1 && File.ReadAllText(data)=="Contents here","complete volume repairs missing output with durable nested anchor");
        Check(Hash(report)==reportHash,"repair preserves published report contents");
        byte[] original=File.ReadAllBytes(data);File.WriteAllText(data,"changed output");
        Invalid(()=>VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null),"volume refuses changed published file");File.WriteAllBytes(data,original);
        string plan=Directory.GetFiles(Path.Combine(root,"ntfs.state","plans"),"*.json").Single();byte[] planBytes=File.ReadAllBytes(plan);
        byte[] damaged=(byte[])planBytes.Clone();damaged[damaged.Length/2]^=1;File.WriteAllBytes(plan,damaged);
        ErrorCode(()=>VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null),"NATIVE_NTFS_PLAN_CHANGED","volume refuses changed immutable stream plan");File.WriteAllBytes(plan,planBytes);
        File.WriteAllText(report,"changed report");
        ErrorCode(()=>VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null),"NATIVE_NTFS_REPORT_CHANGED","volume refuses changed report");

        root=Path.Combine(evidence,"volume-parent-failure");anchor=null;bool fail=true;
        Action<RecoveryMethodCheckpoint> commit=a=>{
            var saved=(Dictionary<string,object>)new JavaScriptSerializer().DeserializeObject(File.ReadAllText(a.Path));
            var payload=(Dictionary<string,object>)saved["Payload"];
            if(fail && Convert.ToInt64(payload["Next"])==42)throw new IOException("injected parent failure");
            anchor=a;
        };
        ErrorCode(()=>VolumeRun(root,image,tools,volume,null,commit,CancellationToken.None,null),"injected parent failure","actual volume cursor parent commit fails before native acknowledgement");
        fail=false;
        Check(VolumeRun(root,image,tools,volume,anchor,commit,CancellationToken.None,null)==1,"volume retries unacknowledged record with completed stream deduplicated by identifiers");
        Check(Directory.GetFiles(Path.Combine(root,"ntfs"),"record-*").Length==1,"parent failure creates no duplicate recovered file");

        root=Path.Combine(evidence,"volume-report-pending");anchor=null;
        using(var stop=new CancellationTokenSource()) {
            try {
                VolumeRun(root,image,tools,volume,null,a=>anchor=a,stop.Token,text=>{if(text=="ntfs: report pending")stop.Cancel();});
                throw new Exception("report publication did not cancel");
            }catch(OperationCanceledException){Check(!File.Exists(Path.Combine(root,"ntfs","ntfs-volume.json")),"report-pending cancellation does not publish a successful report");}
        }
        Check(VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null)==1 && File.Exists(Path.Combine(root,"ntfs","ntfs-volume.json")),"report-pending resume publishes anchored report without rescanning");
    }
    static void LargeVolumeCases(string worker,string image,string expectedPath)
    {
        string sourceHash=Hash(image),expectedHash=Hash(expectedPath);
        var tools=new List<RecoveryNativeToolFile>();
        foreach(string path in new[]{worker}.Concat(Directory.GetFiles(Path.GetDirectoryName(worker),"*.dll")))tools.Add(new RecoveryNativeToolFile {Path=path,Sha256=Hash(path)});
        long volume;using(var source=File.OpenRead(image)){byte[] boot=new byte[512];source.Read(boot,0,512);volume=checked((long)BitConverter.ToUInt64(boot,40)*512);}
        string root=Path.Combine(evidence,"large-native-copy");RecoveryMethodCheckpoint anchor=null;
        using(var stop=new CancellationTokenSource()) {
            try {
                VolumeRun(root,image,tools,volume,null,a=>anchor=a,stop.Token,text=>{if(text.Contains("mapped bytes 1048576 (copy"))stop.Cancel();});
                throw new Exception("large native copy did not cancel");
            }catch(OperationCanceledException){Check(anchor!=null,"native large-file copy commits partial progress before cancellation");}
        }
        var saved=(Dictionary<string,object>)new JavaScriptSerializer().DeserializeObject(File.ReadAllText(anchor.Path));
        var payload=(Dictionary<string,object>)saved["Payload"];
        Check(Convert.ToInt64(payload["Next"])==41 && payload["ActiveFile"]!=null,"native MFT cursor stays on interrupted file with anchored copy");
        Check(!Directory.Exists(Path.Combine(root,"ntfs")) || Directory.GetFiles(Path.Combine(root,"ntfs"),"record-*").Length==0,"interrupted native large file is not published");
        string partial=Directory.GetFiles(Path.Combine(root,"ntfs.state"),"*.partial",SearchOption.AllDirectories).Single();
        string prefixHash=Hash(partial);
        using(var locked=new FileStream(partial,FileMode.Open,FileAccess.Read,FileShare.Read))
            Invalid(()=>VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null),"actual output sharing denial aborts native copy");
        Check(Hash(partial)==prefixHash,"write denial preserves acknowledged partial bytes");
        Check(VolumeRun(root,image,tools,volume,anchor,a=>anchor=a,CancellationToken.None,null)==1,"native large-file copy resumes after output write denial");
        string data=Directory.GetFiles(Path.Combine(root,"ntfs"),"record-*").Single();
        Check(Hash(data)==expectedHash && new FileInfo(data).Length==new FileInfo(expectedPath).Length,"native nonresident output matches independent expected bytes exactly");
        string report=File.ReadAllText(Path.Combine(root,"ntfs","ntfs-volume.json"));
        Check(report.Contains("original_name") && report.Contains(Path.GetFileName(data)) && report.Contains("logical_offset"),"native archive report links source metadata and output logical map");

        root=Path.Combine(evidence,"large-native-parent-failure");anchor=null;bool fail=true;
        Action<RecoveryMethodCheckpoint> commit=a=>{
            var envelope=(Dictionary<string,object>)new JavaScriptSerializer().DeserializeObject(File.ReadAllText(a.Path));
            var state=(Dictionary<string,object>)envelope["Payload"];
            if(fail && state["ActiveFile"]!=null) {
                var link=(Dictionary<string,object>)state["ActiveFile"];
                var child=(Dictionary<string,object>)new JavaScriptSerializer().DeserializeObject(File.ReadAllText(Path.Combine(root,(string)link["Path"])));
                if(Convert.ToInt64(((Dictionary<string,object>)child["Payload"])["Next"])==2*1024*1024)throw new IOException("injected large-file parent failure");
            }
            anchor=a;
        };
        ErrorCode(()=>VolumeRun(root,image,tools,volume,null,commit,CancellationToken.None,null),"injected large-file parent failure","large-file child progress cannot outrun durable parent acknowledgement");
        fail=false;
        Check(VolumeRun(root,image,tools,volume,anchor,commit,CancellationToken.None,null)==1,"native large-file recovery reuses acknowledged prefix after parent failure");
        data=Directory.GetFiles(Path.Combine(root,"ntfs"),"record-*").Single();
        Check(Hash(data)==expectedHash,"discarded orphan copy tail cannot corrupt resumed file");
        Check(Hash(image)==sourceHash,"native large-file cancellation/write/parent failures preserve source image");
    }
    static void RuntimeTools(string worker)
    {
        string runtime=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"tools","native-recovery");Directory.CreateDirectory(runtime);
        var files=new List<object>();
        foreach(string path in new[]{worker}.Concat(Directory.GetFiles(Path.GetDirectoryName(worker),"*.dll"))) {
            string destination=Path.Combine(runtime,Path.GetFileName(path));File.Copy(path,destination);
            Check(Hash(destination)==Hash(path),"owned runtime native tool copied without modification");
            files.Add(new {Name=Path.GetFileName(path),Sha256=Hash(path)});
        }
        string manifestPath=Path.Combine(runtime,"runtime.json");
        string manifest=new JavaScriptSerializer().Serialize(new {Schema=1,Profile="ntfs-plan-v1",Files=files});
        File.WriteAllText(manifestPath,manifest);
        Check(RecoveryNativeTools.Ntfs().Count==5,"packaged-style tool manifest resolved through actual runtime path");
        foreach(string invalid in new[]{manifest.Replace("ntfs-plan-v1","ntfs-plan-v2"),manifest.Replace("ntfs_worker.exe","../ntfs_worker.exe"),
            manifest.Replace("cygwin1.dll","ntfs_worker.exe"),manifest.Replace(Hash(worker),Hash(worker).ToUpperInvariant())}) {
            File.WriteAllText(manifestPath,invalid);
            ErrorCode(()=>RecoveryNativeTools.Ntfs(),"NATIVE_TOOLS_MANIFEST_INVALID","unknown profile/path traversal/duplicate or malformed runtime binding rejected");
        }
        File.WriteAllText(manifestPath,manifest);
    }
    static RecoveryOptions PipelineOptions(bool lost)
    {return new RecoveryOptions {FatMetadata=false,NtfsMetadata=true,LostPartitions=lost,Signatures=false,EmbeddedPhotos=false,Containers=false};}
    static string PipelineFolder(string label,byte[] image)
    {
        string root=Path.Combine(evidence,label);Directory.CreateDirectory(root);string path=Path.Combine(root,"usb.dd");File.WriteAllBytes(path,image);
        File.WriteAllText(Path.Combine(root,"input.sha256"),Hash(path),Encoding.ASCII);return root;
    }
    static void StartPipeline(string root,bool lost,CancellationToken cancel,Action<string> progress)
    {RecoveryPipeline.Run(Path.Combine(root,"usb.dd"),root,PipelineOptions(lost),cancel,progress,Path.Combine(root,"input.sha256"));}
    static void PipelineCases(string worker,string smallImage,string expectedPath)
    {
        RuntimeTools(worker);byte[] original=File.ReadAllBytes(smallImage);string expected=Hash(expectedPath);
        string root=PipelineFolder("pipeline-copy-cancel",original);string sourceHash=Hash(Path.Combine(root,"usb.dd"));
        using(var stop=new CancellationTokenSource()) {
            try {StartPipeline(root,false,stop.Token,text=>{if(text.Contains("mapped bytes 1048576 (copy"))stop.Cancel();});throw new Exception("pipeline did not cancel");}
            catch(OperationCanceledException){checks++;}
        }
        var stage=RecoverySession.Read(root).Stages.Single();
        Check(stage.Key=="ntfs" && stage.Status=="cancelled" && stage.CheckpointSequence>0 && stage.CheckpointPath.StartsWith("ntfs.state/",StringComparison.Ordinal),"actual pipeline persists inner NTFS checkpoint in session");
        RecoveryPipeline.Resume(root,CancellationToken.None,s=>{});stage=RecoverySession.Read(root).Stages.Single();
        Check(stage.Status=="complete" && stage.Candidates==1 && !Directory.Exists(Path.Combine(root,"attempt-history")),"actual session resumes same NTFS attempt to completion");
        var item=RecoveryCatalog.Load(root).Items.Single();
        Check(item.Sha256==expected && item.Name=="File.txt" && item.OriginalPathStatus=="metadata_hint" && item.SourceRanges.Count>0 && item.SourceMapGroups.Count==1,"native file reaches common catalog with name hint and verified physical source map");
        Check(RecoveryCore.RecoveredFiles(root).Count()==1 && Hash(Path.Combine(root,"usb.dd"))==sourceHash,"native metadata reports never become recovered payloads");
        Check(RecoveryPipeline.Resume(root,CancellationToken.None,s=>{}).ResumedStages==1,"completed NTFS pipeline stage reused after artifact verification");

        byte[] backup=(byte[])original.Clone();Array.Clear(backup,0,512);
        // The independent sample was extracted from an original offset of 128
        // sectors. This authored standalone view starts at zero.
        Buffer.BlockCopy(BitConverter.GetBytes(0U),0,backup,backup.Length-512+28,4);
        for(int at=512;at<backup.Length-512;at+=512)
            if(backup[at+510]==0x55 && backup[at+511]==0xaa && Encoding.ASCII.GetString(backup,at+3,8)=="NTFS    ")Array.Clear(backup,at,512);
        root=PipelineFolder("pipeline-backup-boot",backup);sourceHash=Hash(Path.Combine(root,"usb.dd"));
        StartPipeline(root,true,CancellationToken.None,s=>{});
        Check(RecoverySession.Read(root).Stages.All(x=>x.Status=="complete") && RecoveryCatalog.Load(root).Items.Single().Sha256==expected,"lost-partition search restores read-only NTFS boot view from actual backup sector");
        Check(!Directory.GetFiles(root,"working-partition.dd",SearchOption.AllDirectories).Any() && Hash(Path.Combine(root,"usb.dd"))==sourceHash,"backup view avoids full partition copy and preserves damaged primary source");

        const int start=1024*1024;int second=start+original.Length+1024*1024;byte[] disk=new byte[second+original.Length];
        Buffer.BlockCopy(original,0,disk,start,original.Length);Buffer.BlockCopy(original,0,disk,second,original.Length);
        disk[510]=0x55;disk[511]=0xaa;
        for(int index=0;index<2;index++) {
            int begin=index==0?start:second,entry=446+index*16;disk[entry+4]=7;
            Buffer.BlockCopy(BitConverter.GetBytes((uint)(begin/512)),0,disk,entry+8,4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)(original.Length/512)),0,disk,entry+12,4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)(begin/512)),0,disk,begin+28,4);
            Buffer.BlockCopy(disk,begin,disk,begin+original.Length-512,512);
        }
        root=PipelineFolder("pipeline-two-volumes",disk);sourceHash=Hash(Path.Combine(root,"usb.dd"));bool secondVolume=false;
        using(var stop=new CancellationTokenSource()) {
            try {StartPipeline(root,false,stop.Token,text=>{if(text=="ntfs: volume 1 begin")secondVolume=true;if(secondVolume && text=="ntfs: MFT cursor 42")stop.Cancel();});throw new Exception("second volume did not cancel");}
            catch(OperationCanceledException){Check(secondVolume,"second physical NTFS volume interrupted after first volume completion");}
        }
        RecoveryPipeline.Resume(root,CancellationToken.None,s=>{});
        var indexModel=RecoveryCatalog.Load(root);item=indexModel.Items.Single();
        Check(RecoverySession.Read(root).Stages.Single().Candidates==2 && RecoveryCore.RecoveredFiles(root).Count()==2,"multi-volume NTFS engine completes both partition outputs after resume");
        Check(item.Sha256==expected && item.Copies.Count==1 && item.OriginalLocations.Count==2 && item.SourceMapGroups.Count==2,"common catalog deduplicates content while retaining both NTFS source locations");
        Check(Hash(Path.Combine(root,"usb.dd"))==sourceHash && !Directory.Exists(Path.Combine(root,"attempt-history")),"multi-volume session preserves source and completed volume outputs");

        root=PipelineFolder("pipeline-no-ntfs",new byte[4096]);
        string manifestPath=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"tools","native-recovery","runtime.json");
        File.Move(manifestPath,manifestPath+".saved");
        try {
            StartPipeline(root,false,CancellationToken.None,s=>{});
            Check(RecoverySession.Read(root).Stages.Single().Status=="complete" && !RecoveryCatalog.Load(root).Items.Any(),"images without NTFS complete with zero results without requiring or launching native tools");
        }finally {File.Move(manifestPath+".saved",manifestPath);}
    }
    public static int Main(string[] args)
    {
        try {
            evidence=Path.GetFullPath(args[0]); if(Directory.Exists(evidence))throw new IOException("Fresh evidence directory required");Directory.CreateDirectory(evidence);
            string group=args.Length>6?args[6]:"All";
            if(group=="All") {
                DecoderCases();CacheCases();FileCases();NativeScan(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));VolumeCases(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));
                LargeVolumeCases(Path.GetFullPath(args[1]),Path.GetFullPath(args[3]),Path.GetFullPath(args[4]));
            }
            PipelineCases(Path.GetFullPath(args[1]),Path.GetFullPath(args[5]),Path.GetFullPath(args[4]));
            Console.WriteLine("PASS NativeNtfsCheckpoint: "+checks+" checks; group="+group+"; native NTFS controller/pipeline/session/catalog; no packaged or real-device acceptance");return 0;
        } catch(Exception error) {Console.Error.WriteLine(error);return 1;}
    }
}
