// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class FragmentedMediaRecovery
    {
        static string HashReportFile(Stream input,System.Threading.CancellationToken cancel)
        {
            input.Position=0;
            using(var sha=SHA256.Create()) {
                byte[] buffer=new byte[65536];int count;
                while((count=input.Read(buffer,0,buffer.Length))!=0){cancel.ThrowIfCancellationRequested();sha.TransformBlock(buffer,0,count,null,0);}
                sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        static string LimitsIdentity(Limits limits)
        {
            limits.Validate();
            using (var sha=SHA256.Create()) using(var stream=new CryptoStream(Stream.Null,sha,CryptoStreamMode.Write))
            using(var writer=new BinaryWriter(stream,Encoding.UTF8)) {
                writer.Write(limits.MaxCandidates);writer.Write(limits.MaxFiles);writer.Write(limits.MaxOutputBytes);writer.Write(limits.MaxVerifiedBytes);
                writer.Flush();stream.FlushFinalBlock();return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        static bool Digest(string value)
        {return value!=null&&value.Length==64&&value.All(x=>x>='0'&&x<='9'||x>='a'&&x<='f');}
        static void PlanString(BinaryWriter writer,string value)
        {writer.Write(value!=null);if(value!=null)writer.Write(value);}
        static string CandidateIdentity(Context c,Movie movie,List<Extent> extents,bool audioSyntax,string expected)
        {
            using(var sha=SHA256.Create())using(var stream=new CryptoStream(Stream.Null,sha,CryptoStreamMode.Write))
            using(var writer=new BinaryWriter(stream,new UTF8Encoding(false,true))) {
                writer.Write(LimitsIdentity(c.Limits));writer.Write(c.Report.Headers);writer.Write(c.Report.Movies);writer.Write(c.Report.Candidates);
                writer.Write(c.Report.Recovered);writer.Write(c.Report.OutputBytes);writer.Write(c.Report.VerifiedBytes);writer.Write(c.Report.SourceReadBytes);
                writer.Write(c.Report.SourceRangeCount);writer.Write(c.Report.SourceAlternativeCount);writer.Write(c.Report.PayloadProbes);
                writer.Write(c.Report.Files.Count);writer.Write(c.RetainedMetadataBytes);writer.Write(c.LayoutAttempts);
                writer.Write(c.Fmp4States);writer.Write(c.Fmp4MapExtents);writer.Write(c.Fmp4SampleClaims);writer.Write(c.Fmp4ReplayBytes);
                writer.Write(movie.Moov.Offset);writer.Write(movie.Tracks);writer.Write(movie.Chunks.Count);writer.Write(audioSyntax);PlanString(writer,expected);
                writer.Write(extents.Count);
                foreach(var extent in extents) {
                    c.Cancel.ThrowIfCancellationRequested();writer.Write(extent.ImageOffset);writer.Write(extent.LogicalOffset);writer.Write(extent.Length);PlanString(writer,extent.Kind);
                    writer.Write(extent.EquivalentOffsets.Count);foreach(long offset in extent.EquivalentOffsets)writer.Write(offset);
                }
                writer.Flush();stream.FlushFinalBlock();return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        sealed class ReadCheckpoint:IDisposable
        {
            readonly Context owner;
            readonly RecoveryMetadataReads.MetadataReadCheckpoint reader;
            readonly Func<long,int,byte[]> callback;
            public ReadCheckpoint(Context c,RecoveryCheckpointContext context,Action<string> progress)
            {
                if(c.DurableRead!=null)throw new IOException("MEDIA_READ_CONTEXT_INVALID");
                owner=c;var input=c.Input;var verified=c.VerifiedImage;
                var source=new RecoveryMetadataReads.Context(input,c.Cancel,verified,()=>LimitsIdentity(c.Limits),()=> {
                    if(c.Input!=input||c.VerifiedImage!=verified||c.DurableRead!=callback)throw new IOException("MEDIA_READ_OWNER_CHANGED");
                });
                reader=new RecoveryMetadataReads.MetadataReadCheckpoint(source,context,progress);callback=Read;c.DurableRead=callback;
            }
            byte[] Read(long offset,int count)
            {
                byte[] result=new byte[count];
                for(int at=0;at<count;) {int length=Math.Min(1024*1024,count-at);byte[] bytes=reader.ReadBytes(offset+at,length);Buffer.BlockCopy(bytes,0,result,at,length);at+=length;}
                return result;
            }
            public void Finish(){reader.Finish();}
            public void Dispose(){reader.Dispose();owner.DurableRead=null;}
        }
        static Result WriteCandidateCheckpointed(Context c,Movie movie,string folder,List<Extent> extents,bool audioSyntax,string expected,
            RecoveryCheckpointContext context,Action<string> progress)
        {
            string identity=CandidateIdentity(c,movie,extents,audioSyntax,expected);long length=extents.Sum(x=>x.Length);
            var input=c.Input;var verified=c.VerifiedImage;
            var plan=new RecoveryMappedFilePlan {ArchiveRoot=Path.GetDirectoryName(folder),OutputRoot=folder,
                RelativeOutput="candidate-{sha256}.mp4",ContentAddressed=true,ExpectedSha256=expected,Length=length,Provenance=identity,
                Ranges=extents.Select(x=>new RecoveryMappedRange{ImageOffset=x.ImageOffset,LogicalOffset=x.LogicalOffset,Length=x.Length}).ToList()};
            Action guard=()=> {
                if(c.Input!=input||c.VerifiedImage!=verified||CandidateIdentity(c,movie,extents,audioSyntax,expected)!=identity)
                    throw new IOException("MEDIA_CANDIDATE_PLAN_CHANGED");
            };
            string digest;
            using(var publisher=new RecoveryMappedFilePublisher(input,plan,context,c.Cancel,guard,progress,verified))digest=publisher.Run();
            guard();c.Report.SourceReadBytes+=length;
            return CandidateResult(movie,extents,audioSyntax,digest,length);
        }
    }
}
