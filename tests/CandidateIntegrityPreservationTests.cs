using System;
using System.IO;
using System.Linq;
using System.Threading;
using UsbRecovery;

public static class CandidateIntegrityPreservationTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),image=Path.Combine(project,".build","ext4-fixtures-current","signature-hint-pdf.dd"),work=Path.Combine(project,".build","candidate-integrity-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            string before=RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{});Check(Ext4Recovery.Recover(image,work,CancellationToken.None,null)==1,"real e2fsprogs image yields the retained inode candidate");
            var candidate=RecoveryCatalog.Build(work,CancellationToken.None,null).Items.Single();var content=ContentVerifier.Verify(RecoveryCatalog.SafeFile(work,candidate.Path),CancellationToken.None);
            Check(content.Code=="partial","independent format verifier confirms missing PDF termination");
            Check(candidate.Quality=="partial"&&candidate.QualityLabel==content.Label,"consistent inode metadata must not erase a known content problem");
            Check(candidate.Method=="ext4 · запись inode"&&candidate.Status=="Кандидат ext4"&&candidate.SourceRanges.Count>0,"partial content retains its separate metadata origin and byte map");
            var evidence=FileEvidence.Load(work);foreach(string code in new[]{"damaged","partial","encrypted","read_errors","changed","mapping_unknown"}){
                var item=new RecoveredItem{Path=candidate.Path,Sha256=candidate.Sha256,Bytes=candidate.Bytes,Quality=code,QualityLabel="specific finding",IntegrityDetail="independent verifier",Note="",Status=""};
                evidence.Apply(item);Check(item.Quality==code&&item.QualityLabel=="specific finding","origin metadata preserves known "+code+" classification");Check(item.SourceRanges.Count>0&&item.Method=="ext4 · запись inode","origin remains available independently of content classification");
            }
            var unknown=new RecoveredItem{Path=candidate.Path,Sha256=candidate.Sha256,Bytes=candidate.Bytes,Quality="unverified",IntegrityDetail="",Note="",Status=""};evidence.Apply(unknown);Check(unknown.Quality=="metadata_candidate","unknown content still receives bounded metadata-candidate confidence");
            Check(RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{})==before,"catalog/provenance checks preserve source bytes");
            Console.WriteLine("PASS CandidateIntegrityPreservation: "+checks+" checks; real ext4/PDF partial candidate and independent problem classifications retain content findings alongside metadata origin. Synthetic regular files only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
