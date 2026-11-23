// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    public sealed partial class FileEvidence
    {
        static void LoadNativeNtfs(string root,FileEvidence result,Dictionary<string,object> session)
        {
            foreach(var partition in Rows(Read(root,"ntfs/report.json"),"partitions").Take(129)) {
                string reportName=Value(partition,"report");
                if(reportName==null || !Regex.IsMatch(reportName,@"^partition-[0-9]+/ntfs-volume\.json$"))continue;
                var report=Read(root,"ntfs/"+reportName);
                if(report==null || Number(report,"Schema",-1)!=1 || Value(report,"status")!="complete")continue;
                long volumeOffset=Number(report,"volume_offset",-1),volumeBytes=Number(report,"volume_bytes",-1);
                if(volumeOffset<0 || volumeBytes<=0 || volumeOffset>Int64.MaxValue-volumeBytes)continue;
                var candidates=new Dictionary<string,Dictionary<string,object>>(StringComparer.Ordinal);
                foreach(var candidate in Rows(report,"candidates").Take(100001)) {
                    string plan=Value(candidate,"plan_sha256");
                    if(!ValidSha(plan) || candidates.ContainsKey(plan))continue;candidates.Add(plan,candidate);
                }
                foreach(var row in Rows(report,"outputs").Take(100001)) {
                    string name=Value(row,"file"),digest=Value(row,"sha256"),plan=Value(row,"plan_sha256");
                    long size=Number(row,"bytes",-1);Dictionary<string,object> candidate;
                    if(name==null || !Regex.IsMatch(name,@"^record-[0-9]+-[0-9]+-stream-[0-9]+(?:-part-[0-9]{4,})?(?:\.[a-z0-9]{1,10})?$") ||
                        !ValidSha(digest) || size<0 || plan==null || !candidates.TryGetValue(plan,out candidate))continue;
                    string path="ntfs/"+reportName.Substring(0,reportName.IndexOf('/'))+"/data/"+name;
                    RecoveryCatalog.SafeFile(root,path);
                    string original=Value(candidate,"original_name"),parent=Value(candidate,"parent_name");
                    var proof=new EvidenceEntry {Path=path,Kind="ntfs_native_candidate",FileSystem="NTFS",VolumeOffset=volumeOffset,
                        VerifiedSha256=digest,VerifiedBytes=size,VerificationStatus=Value(candidate,"status"),MappingComplete=true,
                        OriginalPath=String.IsNullOrEmpty(original)?null:(String.IsNullOrEmpty(parent)?original:parent.TrimEnd('/','\\')+"/"+original),
                        OriginalPathStatus="metadata_hint",PathEvidence="MFT record and allocation bitmap indicate an unallocated candidate; parent path is a metadata hint",
                        Note="Сохранившаяся запись NTFS. Кластеры могли быть перезаписаны; исходный путь и полнота проверяются отдельно."};
                    BindSource(proof,report,session);
                    if(!String.IsNullOrEmpty(original) && original.Length<=1024 && original.IndexOfAny(new[]{'/','\\','\0'})<0)
                        proof.Components=new List<string>{original};
                    long covered=0;
                    foreach(var range in Rows(row,"ranges")) {
                        long logical=Number(range,"logical_offset",-1),offset=Number(range,"image_offset",-1),bytes=Number(range,"bytes",-1);
                        if(logical!=covered || bytes<=0 || bytes>size-covered || offset<volumeOffset || offset>volumeOffset+volumeBytes-bytes) {
                            proof.MappingComplete=false;break;
                        }
                        proof.Ranges.Add(new FileExtent {Offset=offset,Length=bytes});covered+=bytes;
                    }
                    if(covered!=size || size==0 || !CompleteMap(proof.Ranges,size,proof.SourceBytes)){proof.MappingComplete=false;proof.Ranges.Clear();}
                    if(proof.MappingComplete)proof.Offset=proof.Ranges[0].Offset;
                    result.entries[path]=proof;
                }
            }
        }
        static void ApplyNativeNtfs(RecoveredItem item,EvidenceEntry record)
        {
            if(record.Components!=null && record.Components.Count==1)item.Name=record.Components[0];
            item.Method="NTFS";item.Status=record.VerificationStatus=="missing-segments"?"Часть файла NTFS":"Кандидат NTFS";
            item.Note=record.Note;
            item.IntegrityDetail+=" Имя сохранено из MFT; восстановление цепочки родительских каталогов не подтверждено.";
            if(!record.MappingComplete)item.IntegrityDetail+=" Физическая карта содержимого неполна: resident-данные, разреженные или неинициализированные интервалы.";
            if(record.VerificationStatus=="missing-segments") {
                item.Quality="partial";item.QualityLabel="Восстановлена часть файла";
                item.IntegrityDetail+=" Неизвестные интервалы не заменялись нулями; логическое смещение части указано в отчёте.";
            }
        }
    }
}
