using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class JpegAmbiguityProvenanceTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static List<Dictionary<string,object>> PhotoItems(string run){var value=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(run,"photo-catalog.json")));return ((IEnumerable)value["items"]).Cast<Dictionary<string,object>>().ToList();}
    public static int Main(string[] args)
    {
        try{
            string source=Path.GetFullPath(args[0]),receipt=Path.GetFullPath(args[1]),run=Path.GetFullPath(args[2]);
            Directory.CreateDirectory(Path.Combine(run,"fragmented-photos"));
            var json=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};
            var report=json.Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(Path.Combine(receipt,"report.json")));
            Check(report.Candidates==2&&report.Files.Select(x=>x.Sha256).Distinct().Count()==2,"Source run retained two distinct content witnesses");
            var verify=typeof(FragmentedPhotoRecovery).GetMethod("VerifyMapping",BindingFlags.Static|BindingFlags.NonPublic);
            using(var image=File.OpenRead(source))foreach(var row in report.Files){
                Check(row.Status=="jpeg_gap_ambiguous_candidate"&&row.Note.Contains("not exhaustively enumerated"),"Protocol states ambiguity and bounded alternative coverage");
                string file=Path.Combine(receipt,row.Path);
                verify.Invoke(null,new object[]{image,file,row,CancellationToken.None});
                Check(true,"Actual wrapper mapping validator accepts chosen source-byte replay, separately from original placement");
                File.Copy(file,Path.Combine(run,"fragmented-photos",row.Path));row.Path="fragmented-photos/"+row.Path;
            }
            RecoveryCore.SaveJson(Path.Combine(run,"fragmented-photo-search.json"),report);
            var index=RecoveryCatalog.Build(run,CancellationToken.None,null);
            Check(index.Items.Count==2&&index.Items.All(x=>x.Status=="Неоднозначная сборка"&&x.Quality=="ambiguous_candidate"),"File catalog never promotes an ambiguous witness to a unique structural result");
            Check(index.Items.All(x=>x.SourceRanges.Count==3&&x.SourceRanges.Sum(e=>e.Length)==x.Bytes&&x.OriginalPath==null),"Replayable source maps survive without inventing an original filename");
            var evidence=FileEvidence.Load(run);var item=index.Items[0];
            foreach(string quality in new[]{"damaged","partial","changed","read_errors","encrypted","mapping_unknown"}){
                var known=new RecoveredItem{Path=item.Path,Sha256=item.Sha256,Bytes=item.Bytes,Quality=quality,QualityLabel="existing problem",IntegrityDetail="",Note=""};evidence.Apply(known);
                Check(known.Quality==quality&&known.QualityLabel=="existing problem"&&known.Status=="Неоднозначная сборка","Ambiguity preserves a known "+quality+" content problem");
            }
            Directory.CreateDirectory(Path.Combine(run,"files.1"));
            File.Copy(RecoveryCatalog.SafeFile(run,item.Path),Path.Combine(run,"files.1","copy.jpg"));
            PhotoCatalog.Build(run,CancellationToken.None,null);
            var photos=PhotoItems(run);
            Check(photos.Count==2&&photos.All(x=>(string)x["Status"]=="ambiguous"),"Photo gallery retains ambiguity after successful decoding and byte-identical-copy grouping");
            string html=File.ReadAllText(Path.Combine(run,"Фото.html"));
            Check(html.Contains("Исходный вариант неизвестен")&&html.Contains("i.Status==='ambiguous'"),"Gallery label and default visible filter expose unknown-original candidates");
            index=RecoveryCatalog.Build(run,CancellationToken.None,null);
            Check(index.Items.Count==2&&index.Items.All(x=>x.Quality=="ambiguous_candidate"),"Photo catalog/copy cache cannot erase ambiguity in the main file catalog");
            var row0=report.Files[0];long at=row0.Extents[1].ImageOffset;row0.Extents[1].ImageOffset=row0.Extents[0].ImageOffset+1;
            bool rejected=false;using(var image=File.OpenRead(source))try{verify.Invoke(null,new object[]{image,RecoveryCatalog.SafeFile(run,row0.Path),row0,CancellationToken.None});}catch(TargetInvocationException e){rejected=e.InnerException is IOException;}
            Check(rejected,"Ambiguous status never bypasses the wrapper's disjoint physical mapping validation");row0.Extents[1].ImageOffset=at;
            Console.WriteLine("PASS JpegAmbiguityProvenance: "+checks+" checks; source Python witnesses, actual mapping validator, file/photo catalogs and uncertainty preservation. No packaged helper invocation.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
