using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class FileExtent { public long Offset,Length; }
    public sealed class EvidenceEntry
    {
        public string Path,Kind,Note,VerifiedSha256,VerificationStatus;
        public string OriginalPath,OriginalPathStatus,PathEvidence;
        public string FileSystem,VolumeId,SnapshotId,CheckpointId;
        public List<string> Components;
        public long? VolumeOffset;
        public long VerifiedBytes=-1;
        public List<FileExtent> Ranges=new List<FileExtent>();
        public bool MappingComplete;
        public long? Offset;
    }
    public sealed class FileEvidence
    {
        readonly Dictionary<string,EvidenceEntry> entries=new Dictionary<string,EvidenceEntry>(StringComparer.OrdinalIgnoreCase);
        public List<FileExtent> Unread=new List<FileExtent>();
        public bool HasReadErrors;
        static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=128*1024*1024};}
        public static bool HasUnreadSource(string root,string image=null)
        {
            foreach(string map in new[]{Path.Combine(root,"source-read-errors.json"),image==null?null:image+".read-errors.json"}){
                if(map==null||!File.Exists(map))continue;
                try{
                    if(new FileInfo(map).Length>2L*1024*1024||(File.GetAttributes(map)&FileAttributes.ReparsePoint)!=0)return true;
                    var row=Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(map));
                    if(row==null||Number(row,"unreadBytes",-1)!=0||Rows(row,"ranges").Any()||Value(row,"status")!="complete")return true;
                    long size=Number(row,"size",-1);object ranges;
                    if(size<=0||Number(row,"copied",-1)!=size||image!=null&&new FileInfo(image).Length!=size||!row.TryGetValue("ranges",out ranges)||!(ranges is IEnumerable)||ranges is string)return true;
                }
                catch(IOException){return true;}catch(UnauthorizedAccessException){return true;}catch(ArgumentException){return true;}catch(InvalidOperationException){return true;}
            }
            return HasCapturedReadErrors(root,image);
        }
        static bool HasCapturedReadErrors(string root,string image)
        {
            Dictionary<string,object> source=null;bool sourceLoaded=false;
            foreach(string name in new[]{"capture.json","source-image.json"}){
                try {
                    string file=RecoveryCatalog.SafeFile(root,name);
                    if(!File.Exists(file)||new FileInfo(file).Length>1024*1024)continue;
                    var report=Read(root,name);if(report==null||Value(report,"status")!="complete_with_read_errors")continue;
                    long size=Number(report,"size",-1),unread=Number(report,"unreadBytes",-1);string sha=Value(report,"sha256");
                    if(size<=0||unread<=0||unread>size||sha==null||sha.Length!=64||sha.Any(c=>!Uri.IsHexDigit(c)))continue;
                    if(image!=null&&new FileInfo(image).Length!=size)continue;
                    if(!sourceLoaded){
                        string session=RecoveryCatalog.SafeFile(root,RecoverySession.FileName);
                        if(File.Exists(session)&&new FileInfo(session).Length<=64L*1024*1024)source=Read(root,RecoverySession.FileName);
                        sourceLoaded=true;
                    }
                    // The session binds this report to the image verified by the
                    // pipeline. The missing map cannot turn zero-filled gaps
                    // into evidence of unallocated clusters or intact files.
                    if(source!=null&&Number(source,"SourceBytes",-1)==size&&String.Equals(Value(source,"SourceSha256"),sha,StringComparison.OrdinalIgnoreCase))return true;
                }catch(IOException){continue;}catch(UnauthorizedAccessException){continue;}catch(ArgumentException){continue;}catch(InvalidOperationException){continue;}
            }
            return false;
        }
        static long Number(Dictionary<string,object> row,string key,long fallback=0){object value;try{return row.TryGetValue(key,out value)&&value!=null?Convert.ToInt64(value):fallback;}catch(FormatException){return fallback;}catch(InvalidCastException){return fallback;}catch(OverflowException){return fallback;}}
        static string Value(Dictionary<string,object> row,string key){object value;return row.TryGetValue(key,out value)?Convert.ToString(value):null;}
        void Add(string path,long offset,long length,string kind,bool complete=true)
        {
            if(String.IsNullOrEmpty(path)||offset<0||length<=0||offset>Int64.MaxValue-length)return;
            path=path.Replace('\\','/');var record=new EvidenceEntry{Path=path,Kind=kind,Offset=offset,MappingComplete=complete};record.Ranges.Add(new FileExtent{Offset=offset,Length=length});entries[path]=record;
        }
        static Dictionary<string,object> Read(string root,string relative)
        {
            string file=RecoveryCatalog.SafeFile(root,relative);if(!File.Exists(file)||new FileInfo(file).Length>128L*1024*1024)return null;
            try{object raw=Json().DeserializeObject(File.ReadAllText(file));var record=raw as Dictionary<string,object>;if(record!=null)return record;if(relative=="storage-candidates.json"&&raw is IEnumerable&&!(raw is string))return new Dictionary<string,object>{{"files",raw}};return null;}catch(ArgumentException){return null;}catch(InvalidOperationException){return null;}
        }
        static IEnumerable<Dictionary<string,object>> Rows(Dictionary<string,object> record,string key)
        {
            object values;if(record==null||!record.TryGetValue(key,out values)||!(values is IEnumerable)||values is string)yield break;
            foreach(object value in (IEnumerable)values){var row=value as Dictionary<string,object>;if(row!=null)yield return row;}
        }
        static List<string> Components(Dictionary<string,object> row)
        {
            object raw;if(!row.TryGetValue("original_path_components",out raw)||!(raw is IEnumerable)||raw is string)return null;
            var result=new List<string>();foreach(object value in (IEnumerable)raw){string part=value as string;if(part==null||part.Length==0||part.Length>1024||part=="."||part==".."||part.IndexOf('/')>=0||part.IndexOf('\0')>=0||result.Count>=256)return null;result.Add(part);}return result.Count>0?result:null;
        }
        public static FileEvidence Load(string root)
        {return Load(root,0);}
        static FileEvidence Load(string root,int depth)
        {
            var result=new FileEvidence();var map=Read(root,"source-read-errors.json");
            result.HasReadErrors=HasUnreadSource(root);
            foreach(var range in Rows(map,"ranges")){long offset=Number(range,"Offset",-1),length=Number(range,"Length");if(offset>=0&&length>0&&offset<=Int64.MaxValue-length)result.Unread.Add(new FileExtent{Offset=offset,Length=length});}
            result.Unread=Merge(result.Unread);
            if(map!=null&&Number(map,"unreadBytes",-1)!=result.Unread.Sum(x=>x.Length))result.Unread.Clear();
            foreach(var row in Rows(Read(root,"container-search.json"),"files"))result.Add(Value(row,"path"),Number(row,"offset",-1),Number(row,"bytes"),"container");
            foreach(var row in Rows(Read(root,"extra-photo-search.json"),"files"))result.Add(Value(row,"path"),Number(row,"offset",-1),Number(row,"size"),"embedded_photo");
            foreach(string manifest in new[]{"fragmented-photo-search.json","fragmented-media.json"})foreach(var row in Rows(Read(root,manifest),"Files")){
                string path=Value(row,"Path"),status=Value(row,"Status");long size=Number(row,"Bytes",-1);
                if(String.IsNullOrEmpty(path)||size<=0||!(status=="png_crc_zlib_reassembled_candidate"||status=="jpeg_restart_structural_candidate"||status=="jpeg_gap_structural_candidate"||status=="jpeg_progressive_structural_candidate"||status=="progressive_partial_precision_candidate"||status=="jpeg_restart_huffman_reassembled_candidate"||status=="jpeg_single_gap_huffman_reassembled_candidate"||status=="iso_bmff_structural_candidate"))continue;
                if(!(path.StartsWith("fragmented-photos/",StringComparison.Ordinal)||path.StartsWith("fragmented-media/",StringComparison.Ordinal)))continue;
                var proof=new EvidenceEntry{Path=path,Kind="reassembled_media_candidate",VerifiedSha256=Value(row,"Sha256"),VerifiedBytes=size,VerificationStatus=status,Note=Value(row,"Note"),MappingComplete=true};long logical=0;
                foreach(var extent in Rows(row,"Extents")){
                    long offset=Number(extent,"ImageOffset",-1),at=Number(extent,"LogicalOffset",-1),length=Number(extent,"Length",-1);
                    if(offset<0||length<=0||at!=logical||offset>Int64.MaxValue-length||length>size-logical){proof.MappingComplete=false;break;}
                    proof.Ranges.Add(new FileExtent{Offset=offset,Length=length});logical+=length;
                }
                var sourceRecord=Read(root,RecoverySession.FileName);long sourceBytes=sourceRecord==null?-1:Number(sourceRecord,"SourceBytes",-1),priorEnd=-1;
                foreach(var range in proof.Ranges.OrderBy(x=>x.Offset)){
                    if(range.Offset<priorEnd||sourceBytes>=0&&range.Offset>sourceBytes-range.Length){proof.MappingComplete=false;break;}
                    priorEnd=range.Offset+range.Length;
                }
                if(!proof.MappingComplete||logical!=size){proof.Ranges.Clear();proof.MappingComplete=false;}
                if(proof.Ranges.Count>0)proof.Offset=proof.Ranges[0].Offset;
                result.entries[path.Replace('\\','/')]=proof;
            }
            var ext4=Read(root,"ext4/report.json");
            if(ext4!=null&&Number(ext4,"Schema",-1)==1&&Value(ext4,"Method")=="ext4_retained_deleted_inode"&&Value(ext4,"Status")=="complete"&&Value(ext4,"SourceUnchanged")=="True"&&Value(ext4,"Limited")=="False"&&Value(ext4,"Cancelled")=="False"&&Value(ext4,"Failed")=="False"){
                long sourceBytes=Number(ext4,"InputBytes",-1);string sourceSha=Value(ext4,"SourceSha256");
                var session=Read(root,RecoverySession.FileName);
                bool sourceBound=sourceBytes>0&&sourceSha!=null&&sourceSha.Length==64&&sourceSha.All(Uri.IsHexDigit)&&
                    (session==null||Number(session,"SourceBytes",-1)==sourceBytes&&String.Equals(Value(session,"SourceSha256"),sourceSha,StringComparison.OrdinalIgnoreCase));
                if(sourceBound)foreach(var row in Rows(ext4,"Entries")){
                    string relative=Value(row,"Output"),sha=Value(row,"Sha256");long size=Number(row,"RecoveredBytes",-1);
                    if(relative==null||!relative.StartsWith("files/",StringComparison.Ordinal)||relative.Contains("\\")||relative.Contains("..")||Value(row,"Status")!="deleted_inode_candidate"||size<=0||size!=Number(row,"DeclaredSize",-1)||sha==null||sha.Length!=64||!sha.All(Uri.IsHexDigit))continue;
                    string allocation=Value(row,"AllocationStatus"),mapping=Value(row,"Mapping"),integrity=Value(row,"MappingIntegrity");long volumeOffset=Number(row,"VolumeOffset",-1);
                    if(!(allocation=="currently_free"||allocation=="currently_free_unchecksummed_bitmap")||Number(row,"Inode",0)<=0||Number(row,"DeletionTime",0)<=0||Value(row,"DeletionEvidence")!="free_inode_bitmap_and_zero_links_and_nonzero_dtime")continue;
                    if(!(mapping=="extent_tree"&&(integrity=="inode_and_extent_nodes_crc32c"||integrity=="structural_only_no_metadata_checksum")||mapping=="direct_indirect"&&integrity=="inode_only_indirect_blocks_have_no_checksum"))continue;
                    var volume=Rows(ext4,"Volumes").FirstOrDefault(x=>Number(x,"Offset",-1)==volumeOffset&&Value(x,"Status")=="complete");long volumeBytes=volume==null?-1:Number(volume,"Bytes",-1),inodeOffset=Number(row,"InodeOffset",-1);
                    if(volumeOffset<0||volumeBytes<=0||volumeOffset>sourceBytes-volumeBytes||inodeOffset<volumeOffset||inodeOffset>volumeOffset+volumeBytes-128)continue;
                    string path="ext4/"+relative;RecoveryCatalog.SafeFile(root,path);
                    var proof=new EvidenceEntry{Path=path,Kind="ext4_inode_candidate",VerifiedSha256=sha,VerifiedBytes=size,VerificationStatus=Value(row,"Status"),Note=Value(row,"Note"),MappingComplete=true,FileSystem="ext4",VolumeOffset=Number(row,"VolumeOffset",-1)};
                    long logical=0,priorEnd=-1;
                    foreach(var extent in Rows(row,"Extents")){
                        long at=Number(extent,"LogicalOffset",-1),offset=Number(extent,"ImageOffset",-1),length=Number(extent,"Length",-1);
                        if(at!=logical||offset<volumeOffset||length<=0||length>size-logical||offset>volumeOffset+volumeBytes-length){proof.MappingComplete=false;break;}
                        proof.Ranges.Add(new FileExtent{Offset=offset,Length=length});logical+=length;
                    }
                    foreach(var range in proof.Ranges.OrderBy(x=>x.Offset)){if(range.Offset<priorEnd){proof.MappingComplete=false;break;}priorEnd=range.Offset+range.Length;}
                    if(!proof.MappingComplete||logical!=size||proof.Ranges.Count==0)continue;
                    proof.Offset=proof.Ranges[0].Offset;result.entries[path]=proof;
                }
            }
            foreach(var row in Rows(Read(root,"storage-candidates.json"),"files")){
                string path=Value(row,"path"),original=Value(row,"original_path"),sha=Value(row,"sha256");long bytes=Number(row,"bytes",-1),offset=Number(row,"source_offset_bytes",-1);bool previous=Value(row,"origin")=="previous-version",fallback=Value(row,"checkpoint_fallback")=="True";
                if(path==null||!path.StartsWith("apfs-files/",StringComparison.Ordinal)||original==null||sha==null||bytes<0||offset<0||Value(row,"filesystem")!="APFS"||Value(row,"validation")!="metadata-checksum-and-readable-stream")continue;
                result.entries[path]=new EvidenceEntry{Path=path,Kind=fallback?"apfs_checkpoint":previous?"apfs_snapshot":"apfs_referenced_file",OriginalPath=original,OriginalPathStatus=fallback?"apfs_checkpoint_path":previous?"apfs_snapshot_path":"apfs_referenced_path",PathEvidence="APFS reference; volume="+Value(row,"volume_id")+"; snapshot="+Value(row,"snapshot_id")+"; checkpoint="+Value(row,"checkpoint_xid")+"; inode="+Value(row,"record_id"),VolumeOffset=offset,VerifiedSha256=sha,VerifiedBytes=bytes,FileSystem="APFS",VolumeId=Value(row,"volume_id"),SnapshotId=String.IsNullOrEmpty(Value(row,"snapshot_id"))?null:Value(row,"snapshot_id"),CheckpointId=fallback?Value(row,"checkpoint_xid"):null,Components=Components(row)};
            }
            foreach(var row in Rows(Read(root,"user-signatures.json"),"Files")){
                string path=Value(row,"Path");long offset=Number(row,"Offset",-1),size=Number(row,"Bytes",-1);if(String.IsNullOrEmpty(path)||Value(row,"Status")!="signature_candidate")continue;
                result.Add(path,offset,size,"user_signature");EvidenceEntry proof;if(result.entries.TryGetValue(path.Replace('\\','/'),out proof)){proof.VerifiedSha256=Value(row,"Sha256");proof.VerifiedBytes=size;proof.VerificationStatus="signature_candidate";proof.Note=Value(row,"Boundary");}
            }
            foreach(var row in Rows(Read(root,"text-search.json"),"files"))result.Add(Value(row,"path"),Number(row,"offset",-1),Number(row,"sourceBytes"),"text_fragment");
            foreach(var row in Rows(Read(root,"archive-salvage.json"),"files")){
                string path=Value(row,"Path")??Value(row,"path");long header=Number(row,"HeaderOffset",-1),at=Number(row,"DataOffset",-1),length=Number(row,"CompressedBytes",Number(row,"PackedBytes",0));if(header>=0&&at>=header&&length>=0&&at<=Int64.MaxValue-length)result.Add(path,header,at-header+length,"encoded_zip_entry");
                EvidenceEntry proof;if(path!=null&&result.entries.TryGetValue(path.Replace('\\','/'),out proof)){proof.VerifiedSha256=Value(row,"Sha256");proof.VerifiedBytes=Number(row,"Bytes",-1);proof.VerificationStatus=Value(row,"Status");}
            }
            foreach(var row in Rows(Read(root,"fragmented-zip.json"),"Files")){
                string path=Value(row,"Path");long size=Number(row,"Bytes",-1);if(String.IsNullOrEmpty(path)||size<=0||Value(row,"Status")!="zip_crc_reassembled")continue;
                var proof=new EvidenceEntry{Path=path,Kind="reassembled_zip",VerifiedSha256=Value(row,"Sha256"),VerifiedBytes=size,VerificationStatus=Value(row,"Status"),MappingComplete=true};long logical=0;
                foreach(var extent in Rows(row,"Extents")){
                    long offset=Number(extent,"ImageOffset",-1),at=Number(extent,"LogicalOffset",-1),length=Number(extent,"Length",-1);
                    if(offset<0||length<=0||at!=logical||offset>Int64.MaxValue-length||length>size-logical){proof.MappingComplete=false;break;}
                    proof.Ranges.Add(new FileExtent{Offset=offset,Length=length});logical+=length;
                }
                if(!proof.MappingComplete||logical!=size){proof.Ranges.Clear();proof.MappingComplete=false;}
                if(proof.Ranges.Count>0)proof.Offset=proof.Ranges[0].Offset;
                result.entries[path.Replace('\\','/')]=proof;
            }
            foreach(var row in Rows(Read(root,"metadata-rescue/report.json"),"Entries")){
                string relative=Value(row,"Output");if(String.IsNullOrEmpty(relative))continue;relative="metadata-rescue/"+relative.Replace('\\','/');
                var item=new EvidenceEntry{Path=relative,Kind="ntfs_record",MappingComplete=Value(row,"UsaFixupsRestored")!="True",Offset=Number(row,"RecordOffset",-1),Note=Value(row,"Status"),VerifiedSha256=Value(row,"Sha256"),VerifiedBytes=Number(row,"RecoveredBytes",-1)};
                if(Value(row,"PathStatus")=="verified_parent_chain"){item.OriginalPath=Value(row,"OriginalPath");item.OriginalPathStatus=Value(row,"PathStatus");item.PathEvidence=Value(row,"PathEvidence");item.VolumeOffset=Number(row,"PathVolumeOffset",-1);}
                if(item.MappingComplete)foreach(var extent in Rows(row,"Extents")){long offset=Number(extent,"ImageOffset",-1),length=Number(extent,"Length");if(offset>=0&&length>0&&offset<=Int64.MaxValue-length)item.Ranges.Add(new FileExtent{Offset=offset,Length=length});}
                result.entries[relative]=item;
            }
            string fs=RecoveryCatalog.SafeFile(root,"filesystem/file-extents.jsonl");
            if(File.Exists(fs))using(var reader=new StreamReader(fs)){
                string line;int count=0;while((line=reader.ReadLine())!=null&&count++<100000){if(line.Length>1024*1024)continue;Dictionary<string,object> row;try{row=Json().Deserialize<Dictionary<string,object>>(line);}catch(ArgumentException){continue;}string path=Value(row,"path");if(String.IsNullOrEmpty(path))continue;var item=new EvidenceEntry{Path=path,Kind="filesystem",MappingComplete=Value(row,"mappingComplete")=="True",Note=Value(row,"status")};
                    item.VerifiedSha256=Value(row,"sha256");item.VerifiedBytes=Number(row,"bytes",-1);
                    string original=Value(row,"originalPath");if(original!=null&&!original.StartsWith("/orphan-directory-",StringComparison.Ordinal)){item.OriginalPath=original;item.OriginalPathStatus="filesystem_candidate";item.PathEvidence=Value(row,"nameEvidence");item.VolumeOffset=Number(row,"volumeOffset",-1);}
                    foreach(var extent in Rows(row,"ranges")){long offset=Number(extent,"Offset",-1),length=Number(extent,"Length");if(offset>=0&&length>0&&offset<=Int64.MaxValue-length)item.Ranges.Add(new FileExtent{Offset=offset,Length=length});}if(item.Ranges.Count>0)item.Offset=item.Ranges[0].Offset;result.entries[path]=item;
                }
            }
            string history=RecoveryCatalog.SafeFile(root,"attempt-history");if(depth==0&&Directory.Exists(history)){
                var attempts=Directory.EnumerateDirectories(history).Take(257).ToArray();if(attempts.Length>256)throw new IOException("Слишком много предыдущих попыток.");
                foreach(string attempt in attempts){string prefix="attempt-history/"+Path.GetFileName(attempt)+"/";RecoveryCatalog.SafeFile(root,prefix+"guard");var prior=Load(attempt,1);foreach(var row in prior.entries){row.Value.Path=prefix+row.Value.Path;result.entries[prefix+row.Key]=row.Value;}}
            }
            return result;
        }
        public EvidenceEntry For(string path){EvidenceEntry row;return entries.TryGetValue(path.Replace('\\','/'),out row)?row:null;}
        public long Intersections(IEnumerable<FileExtent> ranges)
        {
            var source=Merge(ranges);long total=0;int left=0,right=0;
            while(left<source.Count&&right<Unread.Count){var a=source[left];var b=Unread[right];long start=Math.Max(a.Offset,b.Offset),end=Math.Min(a.Offset+a.Length,b.Offset+b.Length);if(end>start)total+=end-start;if(a.Offset+a.Length<=b.Offset+b.Length)left++;else right++;}return total;
        }
        static List<FileExtent> Merge(IEnumerable<FileExtent> ranges)
        {
            var result=new List<FileExtent>();foreach(var row in ranges.Where(x=>x.Offset>=0&&x.Length>0&&x.Offset<=Int64.MaxValue-x.Length).OrderBy(x=>x.Offset).ThenBy(x=>x.Length)){
                if(result.Count==0||row.Offset>result[result.Count-1].Offset+result[result.Count-1].Length)result.Add(new FileExtent{Offset=row.Offset,Length=row.Length});
                else {var prior=result[result.Count-1];prior.Length=Math.Max(prior.Offset+prior.Length,row.Offset+row.Length)-prior.Offset;}
            }return result;
        }
        static bool PreserveProblem(RecoveredItem item){return new[]{"partial","damaged","changed","read_errors","encrypted","mapping_unknown"}.Contains(item.Quality);}
        public void Apply(RecoveredItem item)
        {
            item.OriginalLocations=new List<OriginalLocation>();item.OriginalPath=item.OriginalPathStatus=item.OriginalPathEvidence=item.SourceCandidatePath=null;item.SourceVolumeOffset=null;item.SourceOffset=null;item.SourceRanges=new List<FileExtent>();item.UnreadBytes=null;
            foreach(string candidate in new[]{item.Path}.Concat(item.Copies)){
                var origin=For(candidate);if(origin==null||origin.OriginalPath==null||origin.VerifiedSha256==null||!String.Equals(origin.VerifiedSha256,item.Sha256,StringComparison.OrdinalIgnoreCase)||origin.VerifiedBytes!=item.Bytes)continue;
                item.OriginalLocations.Add(new OriginalLocation{Path=origin.OriginalPath,Status=origin.OriginalPathStatus,Evidence=origin.PathEvidence,VolumeOffset=origin.VolumeOffset.HasValue&&origin.VolumeOffset.Value>=0?origin.VolumeOffset:null,CandidatePath=candidate,FileSystem=origin.FileSystem,VolumeId=origin.VolumeId,SnapshotId=origin.SnapshotId,CheckpointId=origin.CheckpointId,Components=origin.Components});
            }
            var preferred=item.OriginalLocations.FirstOrDefault(x=>x.Status=="verified_parent_chain")??item.OriginalLocations.FirstOrDefault(x=>x.Status=="apfs_referenced_path")??item.OriginalLocations.FirstOrDefault();
            if(preferred!=null){item.OriginalPath=preferred.Path;item.OriginalPathStatus=preferred.Status;item.OriginalPathEvidence=preferred.Evidence;item.SourceVolumeOffset=preferred.VolumeOffset;}
            var record=For(preferred==null?item.Path:preferred.CandidatePath);
            if(record==null&&preferred==null)record=item.Copies.Select(For).FirstOrDefault(x=>x!=null&&x.Kind=="ext4_inode_candidate"&&x.VerifiedBytes==item.Bytes&&String.Equals(x.VerifiedSha256,item.Sha256,StringComparison.OrdinalIgnoreCase));
            if(record!=null&&record.VerifiedSha256!=null&&(!String.Equals(record.VerifiedSha256,item.Sha256,StringComparison.OrdinalIgnoreCase)||record.VerifiedBytes!=item.Bytes)){
                item.Quality="changed";item.QualityLabel="Изменён после извлечения";item.IntegrityDetail+=" Прежняя карта источника не применяется: текущий файл не совпадает с манифестом извлечения.";record=null;
            }
            if(record!=null){item.SourceCandidatePath=record.Path;item.SourceOffset=record.Offset;item.SourceRanges=record.Ranges;item.IntegrityDetail+=(String.IsNullOrEmpty(item.IntegrityDetail)?"":" ")+"Происхождение: "+record.Kind+"; диапазонов в образе: "+record.Ranges.Count+".";}
            if(record!=null&&record.Kind=="ntfs_record"&&!record.MappingComplete)item.IntegrityDetail+=" Для resident-данных восстановлены USA-байты записи; указан адрес записи, а точная физическая карта содержимого не заявляется.";
            if(record!=null&&record.Kind=="encoded_zip_entry")item.IntegrityDetail+=" Диапазон относится к закодированной ZIP-записи с заголовком, а не к несжатому содержимому.";
            if(record!=null&&(record.Kind=="apfs_snapshot"||record.Kind=="apfs_checkpoint"||record.Kind=="apfs_referenced_file")){if(record.Components!=null&&record.Components.Count>0){item.Name=record.Components[record.Components.Count-1];int dot=item.Name.LastIndexOf('.');item.Extension=dot>=0?item.Name.Substring(dot):"";item.Category=RecoveryCatalog.Category(item.Extension);}item.Method=record.Kind=="apfs_checkpoint"?"APFS · предыдущее состояние":record.Kind=="apfs_snapshot"?"APFS · снимок":"APFS · файл";item.Status=record.Kind=="apfs_referenced_file"?"Сохранившийся файл APFS":"Предыдущая версия APFS";item.Note="Файл прочитан по сохранившейся записи APFS; факт удаления не устанавливается. Снимок, том и запись приведены в происхождении. SHA256 удостоверяет полученные байты, а не исходную полноту.";item.IntegrityDetail+=" "+record.PathEvidence+"; физическая карта блоков не установлена.";}
            if(record!=null&&record.Kind=="reassembled_zip")item.IntegrityDetail+=" ZIP собран из раздельных записей; проверены размеры и CRC элементов. Исходное имя, факт удаления и подлинность содержимого неизвестны.";
            if(record!=null&&(record.Note=="partial"||record.Note=="partial_candidate")){item.Quality="partial";item.QualityLabel="Восстановлена часть файла";item.IntegrityDetail+=" Карта метаданных показывает неполное восстановление; открытие файла не доказывает полноту.";}
            if(record!=null&&record.Kind=="reassembled_media_candidate"){
                item.Method="Сборка разрозненных медиа";item.Status="Кандидат сборки";
                if(!PreserveProblem(item)){item.Quality="structural_candidate";item.QualityLabel="Структура согласована";}
                item.Note="Сборка из сохранившихся фрагментов. Принадлежность к исходному файлу и факт удаления не подтверждены. Проверь фотографию или весь ролик.";
                item.IntegrityDetail+=" "+record.Note+" SHA256 фиксирует полученную сборку, а не исходное содержимое.";
                if(record.VerificationStatus=="progressive_partial_precision_candidate"){if(!PreserveProblem(item))item.QualityLabel="JPEG с частичной точностью";item.Note+=" Сохранились не все уровни точности progressive JPEG; сравни детали изображения.";}
            }
            if(record!=null&&record.Kind=="ext4_inode_candidate"){
                item.Method="ext4 · запись inode";item.Status="Кандидат ext4";
                if(!PreserveProblem(item)){item.Quality="metadata_candidate";item.QualityLabel="Метаданные согласованы";}
                item.SourceVolumeOffset=record.VolumeOffset;
                item.Note="Сохранилась карта удалённого inode. Блоки свободны в этом образе, но могли быть перезаписаны после удаления. Исходное имя и содержимое не подтверждены.";
                item.IntegrityDetail+=" "+record.Note+" Ссылки каталогов без поколения inode приведены только в ext4/report.json; исходный путь по ним не восстанавливается.";
            }
            if(!HasReadErrors)return;
            if(record!=null&&record.MappingComplete&&record.Ranges.Count>0&&Unread.Count>0){
                long bytes=Intersections(record.Ranges);item.UnreadBytes=bytes;
                if(bytes>0){item.Quality="read_errors";item.QualityLabel="Есть непрочитанные байты";item.IntegrityDetail+=" Подтверждено пересечение с картой ошибок: "+bytes+" исходных байт заменены нулями.";}
                else item.IntegrityDetail+=" Подтверждённые диапазоны не пересекают известные пропуски образа; это не проверка первоначального содержимого.";
            }else{item.UnreadBytes=null;item.IntegrityDetail+=" В образе есть пропуски, но точное пересечение для этого файла не установлено.";if(item.Quality=="unverified"){item.Quality="mapping_unknown";item.QualityLabel="Положение пропусков неизвестно";}}
        }
    }
}
