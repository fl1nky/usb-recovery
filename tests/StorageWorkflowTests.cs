using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using UsbRecovery;

// Only generated member images are opened. This is workflow verification,
// not a claim about any physical device or encrypted user volume.
public static class StorageWorkflowTests
{
    static int checks;
    static string work;
    static void Check(bool value, string description)
    {
        checks++;
        if (!value) throw new Exception(description);
    }
    static void Reject<T>(Action action, string description) where T : Exception
    {
        try { action(); }
        catch (T) { Check(true, description); return; }
        throw new Exception(description);
    }
    static StorageRecoveryRequest Request()
    {
        return new StorageRecoveryRequest {
            Kind = "RAID", OutputDirectory = Path.Combine(work, "results"),
            MaximumOutputBytes = 4096, Secrets = new Dictionary<string, string>(),
            Raid = new RaidConfiguration {
                Level = "0", Layout = "striped", ChunkSize = 512,
                Members = new List<RaidMember> {
                    new RaidMember { Path = Path.Combine(work, "one.dd") },
                    new RaidMember { Path = Path.Combine(work, "two.dd") }
                }
            }
        };
    }
    static void Validate()
    {
        Reject<ArgumentNullException>(() => StorageRecoveryWorkflow.Validate(null), "missing request rejected");
        var request = Request();
        request.Kind = "unknown";
        Reject<IOException>(() => StorageRecoveryWorkflow.Create(request), "unknown source rejected before output creation");
        Check(!Directory.Exists(request.OutputDirectory), "invalid request creates no output directory");
        request.Kind = "APFS";
        Reject<IOException>(() => StorageRecoveryWorkflow.Validate(request), "missing APFS selection rejected");
        request.Volume = new StorageVolumeInfo { Kind = "BitLocker" };
        Reject<IOException>(() => StorageRecoveryWorkflow.Validate(request), "selection from another mode rejected");
        request.Volume.Kind = "APFS";
        StorageRecoveryWorkflow.Validate(request);
        Check(true, "selected APFS volume accepted without touching a device");
        request = Request();
        request.MaximumOutputBytes = 2047;
        Reject<IOException>(() => StorageRecoveryWorkflow.Create(request), "derived RAID output limit enforced");
        request.Raid.Level = "RAID-0";
        Reject<IOException>(() => StorageRecoveryWorkflow.Create(request), "same output limit enforced for supported RAID alias");
        request.MaximumOutputBytes = 4096;
        request.Raid.LogicalSize = 4097;
        Reject<IOException>(() => StorageRecoveryWorkflow.Create(request), "explicit RAID output limit enforced");
        request.MaximumOutputBytes = 0;
        Reject<IOException>(() => StorageRecoveryWorkflow.Create(request), "zero output limit rejected");
        Check(!Directory.Exists(request.OutputDirectory), "validation failures leave results untouched");
    }
    static void StorageResumeRequests()
    {
        foreach(string kind in new[]{"APFS","BitLocker"}){
            var request=new StorageRecoveryRequest{Kind=kind,Source=Path.Combine(work,"one.dd"),
                OutputDirectory=Path.Combine(work,"storage-results"),MaximumOutputBytes=4096,MaximumSnapshots=3,
                Volume=new StorageVolumeInfo{Kind=kind,OffsetBytes=0,LengthBytes=1024},
                IncludeSnapshots=true,SearchAfterPreparation=true,MaximumSearch=true,
                Secrets=new Dictionary<string,string>{{"password","Generated-secret-do-not-persist-19627"}}};
            var execution=StorageRecoveryWorkflow.Create(request);
            string saved=File.ReadAllText(Path.Combine(execution.Directory,"storage-request.json"));
            Check(!saved.Contains("Generated-secret")&&!saved.Contains("Secrets")&&!saved.Contains("password"),"resume plan whitelists nonsecret fields");
            var loaded=StorageRecoveryWorkflow.ReadResumeRequest(execution.Directory);
            Check(loaded.Secrets==null&&loaded.Kind==kind&&loaded.Volume.LengthBytes==1024&&loaded.MaximumSnapshots==3,"resume restores source selection without credentials");
            Check(StorageRecoveryWorkflow.Resume(loaded,execution.Directory).ResumePreparation,"preparation can resume before a helper has started");
            loaded.Secrets=new Dictionary<string,string>{{"recovery_password","Different-ephemeral-secret"}};
            Check(StorageRecoveryWorkflow.Resume(loaded,execution.Directory).ResumePreparation,"fresh credentials do not change persistent preparation identity");
            loaded.MaximumOutputBytes++;
            Reject<IOException>(()=>StorageRecoveryWorkflow.Resume(loaded,execution.Directory),"changed output limits cannot silently reuse checkpoint");
            loaded.MaximumOutputBytes--;loaded.Volume.OffsetBytes=512;
            Reject<IOException>(()=>StorageRecoveryWorkflow.Resume(loaded,execution.Directory),"changed partition cannot reuse checkpoint");
            File.WriteAllText(Path.Combine(execution.Directory,"storage-request.json"),"{\"Schema\":999}");
            Reject<IOException>(()=>StorageRecoveryWorkflow.ReadResumeRequest(execution.Directory),"unknown resume schema rejected");
        }
    }

    static StorageRecoveryExecution Prepare()
    {
        var request = Request();
        var execution = StorageRecoveryWorkflow.Create(request);
        using (var cancelled = new CancellationTokenSource()) {
            cancelled.Cancel();
            Reject<OperationCanceledException>(
                () => StorageRecoveryWorkflow.Execute(request, execution, cancelled.Token, null),
                "cancelled workflow never starts preparation");
        }
        Check(execution.Prepared == null && execution.Catalog == null, "cancelled preparation publishes no result");
        Check(!Directory.Exists(Path.Combine(execution.Directory, "raid")), "cancel before start writes no RAID output");

        request.SearchAfterPreparation = true;
        using (var cancellation = new CancellationTokenSource()) {
            Reject<OperationCanceledException>(() => StorageRecoveryWorkflow.Execute(request, execution,
                cancellation.Token, stage => {
                    if (stage.Title == "Образ RAID собран и проверен") cancellation.Cancel();
                }), "cancellation between preparation and search is propagated");
        }
        Check(execution.Prepared != null && File.Exists(execution.Prepared.Image),
            "completed preparation survives a cancelled following search");
        Check(File.Exists(execution.Prepared.Checksum), "prepared image retains its verification checksum");
        Check(execution.Catalog == null && execution.Index == null, "cancelled search publishes no successful catalog");
        byte[] expected = Enumerable.Repeat((byte)0x11, 512)
            .Concat(Enumerable.Repeat((byte)0x22, 512))
            .Concat(Enumerable.Repeat((byte)0x11, 512))
            .Concat(Enumerable.Repeat((byte)0x22, 512)).ToArray();
        Check(File.ReadAllBytes(execution.Prepared.Image).SequenceEqual(expected), "RAID workflow preserves expected literal stripe order");
        return execution;
    }
    static void Search(StorageRecoveryExecution execution)
    {
        string valid = StorageRecoveryWorkflow.SearchPrepared(execution, false, CancellationToken.None, null);
        Check(valid == execution.Catalog && execution.Index != null, "retry publishes a readable catalog");
        Check(File.Exists(Path.Combine(valid, "result.json")), "retry retains search report");
        var previous = execution.Index;
        bool corrupted = false;
        Reject<IOException>(() => StorageRecoveryWorkflow.SearchPrepared(execution, false,
            CancellationToken.None, stage => {
                if (stage.Key != "finished") return;
                string newest = Directory.GetDirectories(execution.Directory, "search-*")
                    .Single(path => path != valid);
                File.WriteAllText(Path.Combine(newest, "files-index.json"), "{");
                corrupted = true;
            }), "corrupt completed catalog cannot report success");
        Check(corrupted, "catalog failure injected after actual search completion");
        Check(execution.Catalog == valid && Object.ReferenceEquals(execution.Index, previous),
            "failed search keeps the last verified catalog");
        Check(File.Exists(execution.Prepared.Image), "failed catalog validation retains prepared image for retry");
    }
    public static int Main(string[] args)
    {
        string project = Path.GetFullPath(args[0]);
        work = Path.Combine(project, ".build", "workflow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        try {
            File.WriteAllBytes(Path.Combine(work, "one.dd"), Enumerable.Repeat((byte)0x11, 1024).ToArray());
            File.WriteAllBytes(Path.Combine(work, "two.dd"), Enumerable.Repeat((byte)0x22, 1024).ToArray());
            Validate();
            StorageResumeRequests();
            Search(Prepare());
            Check(File.ReadAllBytes(Path.Combine(work, "one.dd")).All(value => value == 0x11) &&
                File.ReadAllBytes(Path.Combine(work, "two.dd")).All(value => value == 0x22), "source members unchanged");
            Console.WriteLine("PASS StorageWorkflow: " + checks + " checks; generated images, validation, cancellation, prepared-image retry and invalid-catalog publication.");
            return 0;
        } catch (Exception error) {
            Console.Error.WriteLine(error);
            return 1;
        } finally {
            if (Path.GetFullPath(work).StartsWith(Path.Combine(project, ".build", "workflow-"), StringComparison.OrdinalIgnoreCase))
                Directory.Delete(work, true);
        }
    }
}
