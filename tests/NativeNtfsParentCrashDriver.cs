// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Threading;
using UsbRecovery;

// Hosts the actual packaged product assembly. The parent test terminates this
// process while its owned native worker is awaiting a durable stream reply.
public static class NativeNtfsParentCrashDriver
{
    public static int Main(string[] args)
    {
        try {
            string mode=args[0],image=Path.GetFullPath(args[1]),output=Path.GetFullPath(args[2]);
            if(mode=="start") {
                Directory.CreateDirectory(output);string checksum=Path.Combine(output,"input.sha256");
                File.WriteAllText(checksum,RecoveryCore.HashFile(image,CancellationToken.None,(n,total)=>{}));
                var options=new RecoveryOptions {FatMetadata=false,NtfsMetadata=true,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false};
                RecoveryPipeline.Run(image,output,options,CancellationToken.None,message=>{
                    if(message.Contains("mapped bytes 1048576 (copy")) {
                        Console.WriteLine("PARENT_CRASH_POINT_AFTER_DURABLE_MIB");Console.Out.Flush();Thread.Sleep(Timeout.Infinite);
                    }
                },checksum);
                throw new IOException("Owned crash point was not reached");
            }
            if(mode!="resume")throw new IOException("Unknown owned test mode");
            var result=RecoveryPipeline.Resume(output,CancellationToken.None,message=>{});
            return result.Candidates==1 && result.UniqueFiles==1?0:2;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
